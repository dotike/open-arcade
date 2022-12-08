#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
narc_k8s --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.7'

import asyncio
import boto3
import argparse
import datetime
import os
import sys
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
import base64
import binascii
import logging
import json
import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import time
import re
from arclib.asteroid import Asteroid
from arclib import log, common, k8s, storage
from arclib import narc_ingress as narc_ingress


# --------------------------------------------------------------------
#
# NoAliasDumper
#
# --------------------------------------------------------------------
class NoAliasDumper(yaml.SafeDumper):
    """Turn off Anchors and Aliases for YAML safe_dump."""

    def ignore_aliases(self, data):
        """Set ignore_aliases to true."""
        return True


# --------------------------------------------------------------------
#
# create_external_named_service
#
# --------------------------------------------------------------------
def create_external_named_service(arcade_name, rds_host_name, narc_id, asteroid_name):
    """Create a named service that points at the host name of the RDS instance so it can be referenced like any asteroid service."""

    # Create short service name by truncating narc_id to everything after the second "-"
    short_service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]

    k8sservicemeta = {'name': short_service_name, 'namespace': asteroid_name}
    k8sservicebody = {'apiVersion': "v1",
                      'kind': "Service",
                      'metadata': k8sservicemeta,
                      'spec': {'type': 'ExternalName',
                               'externalName': rds_host_name}}

    # print(yaml.dump(k8sservicebody, Dumper=NoAliasDumper))
    _create_namespace(arcade_name, narc_id, asteroid_name) # idempotent
    k8s.load_arcade_k8s_config(arcade_name)
    k8s_core_v1 = client.CoreV1Api()
    try:
        core_response = k8s_core_v1.create_namespaced_service(
            body=k8sservicebody, namespace=asteroid_name, pretty='false')
    except ApiException as k8serror:
        logging.error(k8serror)
        return False

    logging.info(core_response)
    return True


# --------------------------------------------------------------------
#
# delete_external_named_service
#
# --------------------------------------------------------------------
def delete_external_named_service(arcade_name, narc_id, asteroid_name):
    """Remove a named service in kubernetes that was pointed at the RDS instance hostname."""
    k8s.load_arcade_k8s_config(arcade_name)
    k8s_core_v1 = client.CoreV1Api()
    short_service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]
    try:
        delete_service = k8s_core_v1.delete_namespaced_service(
            name=short_service_name, namespace=asteroid_name)
        logging.info(delete_service)
        return delete_service
    except ApiException as k8serror:
        logging.error(k8serror)
        return False


# --------------------------------------------------------------------
#
# get_all_services
#
# --------------------------------------------------------------------
def get_all_services():
    """Query K8s for all narc services"""
    k8s_apps_v1 = client.AppsV1Api()
    try:
        V1DeploymentList = k8s_apps_v1.list_deployment_for_all_namespaces(timeout_seconds=10)

        if hasattr(V1DeploymentList, "items"):

            # Filter only narc deployments
            narc_deployments = []
            for deployment in V1DeploymentList.items:
                if re.search("^narc-", deployment.metadata.name):
                    narc_deployments.append(deployment)
            return narc_deployments

        return []
    except ApiException as e:
        logging.error(
            "Exception when calling AppsV1Api->list_deployment_for_all_namespaces: %s\n"
            % e
        )
        sys.exit(1)


# --------------------------------------------------------------------
#
# get_events_for_services
#
# --------------------------------------------------------------------
def get_events_for_service(asteroid_name):
    v1 = client.CoreV1Api()

    namespace = asteroid_name

    try:
        api_response = v1.list_namespaced_event(namespace, watch=False)
    except ApiException as e:
        logging.error(
            "Exception when calling ->list_namespaced_event: %s\n" % e
        )

    events = []
    if api_response.items:
        TIME_FORMAT = "%FT%TZ"
        for item in api_response.items:
            event = {
                "timestamp": item.first_timestamp.strftime(TIME_FORMAT),
                "message": "({}) {}".format(item.type, item.message),
            }
            events.append(event)
    return events


# --------------------------------------------------------------------
#
# getasdfile
#
# --------------------------------------------------------------------
def getasdfile(s3_resource, bucket, filename):
    """Download file from S3 and translate it to k8s yaml.

    :param s3_resource: S3 resource to work with
    :param bucket: Bucket to download from
    :param filename: File to download
    :return: ASD python object
    """
    try:
        content_object = s3_resource.Object(bucket, filename)
        file_content = content_object.get()['Body'].read().decode('utf-8')
    except ClientError as e:
        logging.error('AWS error: {}'.format(e))
        sys.exit(1)
    except NoCredentialsError as crede:
        logging.error('AWS error: {}'.format(crede))
        sys.exit(1)

    try:
        json_content = json.loads(file_content)
    except ValueError as err:
        logging.error('JSON schema error: {}'.format(err))
        sys.exit(1)
    logging.info(json_content)
    return json_content


# --------------------------------------------------------------------
#
# get_k8s_info
#
# --------------------------------------------------------------------
def get_k8s_info(asddata):
    """Create dictionary of running k8s deployment attributes."""
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    # Create short service name by truncating narc_id to everything after the second "-"
    short_service_name = narcid[narcid.find('-', narcid.find('-') + 1) + 1:]

    k8s_apps_v1 = client.AppsV1Api()
    k8s_core_v1 = client.CoreV1Api()
    try:
        deployment = k8s_apps_v1.read_namespaced_deployment(name=narcid, namespace=asteroid_name, pretty='false')
        service = k8s_core_v1.read_namespaced_service(name=short_service_name, namespace=asteroid_name)
        deployment_data = {}
        # deployment_data['narc_id'] = deployment.metadata.name
        # deployment_data['asteroid_name'] = asteroid_name
        if deployment.status.available_replicas == deployment.status.replicas:
            deployment_data['status'] = "ACTIVE"
        else:
            deployment_data['status'] = "PENDING"
        deployment_data['ready'] = deployment.status.available_replicas
        deployment_data['replicas'] = deployment.status.replicas
        deployment_data['creation_timestamp'] = deployment.metadata.creation_timestamp
        deployment_data['last_update_time'] = deployment.status.conditions[0].last_update_time
        service_data = {}
        # service_data['narc_id'] = service.metadata.name
        # service_data['asteroid_name'] = asteroid_name
        service_data['creation_timestamp'] = service.metadata.creation_timestamp
        service_data['ports'] = []
        for v1serviceport in service.spec.ports:
            dict_port = vars(v1serviceport)
            dict_port.pop('local_vars_configuration')
            service_data['ports'].append(dict_port)
        # service_data['ports'] = json.loads(json.dumps(service.spec.ports[0], default=lambda o: o.__dict__, sort_keys=False, indent=4))
        service_data['type'] = service.spec.type
        return deployment_data, service_data
    except ApiException as e:
        # Ignoring 404 errors acceptable it's possible the object doesn't exist and should be handled accordingly
        # logging.error("Exception when calling AppsV1Api->read_namespaced_deployment: %s\n" % e)
        return {}, {}


# --------------------------------------------------------------------
#
# get_k8s_data
#
# --------------------------------------------------------------------
def get_k8s_data(asddata):
    """Query kubernetes for details of deployments"""
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    # Create short service name by truncating narc_id to everything after the second "-"
    short_service_name = narcid[narcid.find('-', narcid.find('-') + 1) + 1:]


    k8s_apps_v1 = client.AppsV1Api()
    k8s_core_v1 = client.CoreV1Api()

    try:
        deployment = k8s_apps_v1.read_namespaced_deployment(name=narcid, namespace=asteroid_name, pretty='false')
        service = k8s_core_v1.read_namespaced_service(name=short_service_name, namespace=asteroid_name)

        return deployment, service
    except ApiException as e:
        # Ignoring 404 errors acceptable it's possible the object doesn't exist and should be handled accordingly
        # logging.error(f"Exception when calling AppsV1Api->read_namespaced_deployment: {e}")
        return {}, {}


# --------------------------------------------------------------------
#
# get_k8s_configmap
#
# --------------------------------------------------------------------
def get_k8s_configmap(asddata):
    """Query kubernetes for details of configmap"""
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    k8s_core_v1 = client.CoreV1Api()

    try:
        configmap = k8s_core_v1.read_namespaced_config_map(name=narcid, namespace=asteroid_name, pretty='false')

        return configmap
    except ApiException as e:
        # Ignoring 404 errors acceptable it's possible the object doesn't exist and should be handled accordingly
        # logging.error(f"Exception when calling AppsV1Api->read_namespaced_deployment: {e}")
        return None


# --------------------------------------------------------------------
#
# get_k8s_secrets
#
# --------------------------------------------------------------------
def get_k8s_secrets(asddata):
    """Query kubernetes for details of secrets configmap"""
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    k8s_core_v1 = client.CoreV1Api()

    try:
        configmap = k8s_core_v1.read_namespaced_secret(name=f"{narcid}-secrets", namespace=asteroid_name,
                                                           pretty='false')

        return configmap
    except ApiException as e:
        # Ignoring 404 errors acceptable it's possible the object doesn't exist and should be handled accordingly
        # logging.error(f"Exception when calling AppsV1Api->read_namespaced_deployment: {e}")
        return None


# --------------------------------------------------------------------
#
# get_k8s_configs
#
# --------------------------------------------------------------------
def get_k8s_configs(asddata, num_configmap):
    """Query kubernetes for details of config file configmap"""
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    k8s_core_v1 = client.CoreV1Api()

    try:
        configmap = k8s_core_v1.read_namespaced_config_map(name=f"{narcid}-configs{num_configmap}",
                                                           namespace=asteroid_name, pretty='false')

        return configmap
    except ApiException as e:
        # Ignoring 404 errors acceptable it's possible the object doesn't exist and should be handled accordingly
        # logging.error(f"Exception when calling AppsV1Api->read_namespaced_deployment: {e}")

        raise e


# --------------------------------------------------------------------
#
# translatek8sdeployment
#
# --------------------------------------------------------------------
def translatek8sdeployment(arcade_name, asddata, k8ssecretsbody, k8sbinarysecretsbody, k8sconfigslist,
                           k8sbinaryconfigsbody):
    """Translate asd python object to k8s deployment python object.

    :param asddata: ASD python object
    :return: k8sdeploybody
    """
    labels = {'infrastructure': asddata['service'], 'version': str(asddata['version'])}
    # Add custom tags
    for key, value in asddata['tags'].items():
        labels[key] = value

    replicas = asddata['service_options']['desired_count']
    if 'retries' in asddata['service_options']:
        retries = asddata['service_options']['retries']
    else:
        # Default number of 10 second retries before assuming the service failed to start.
        retries = 18
    # print(f"Retries: {retries}")

    k8sdeploymeta = {'name': asddata['service'], 'labels': labels}
    k8sdeploystrategy = {'type': 'RollingUpdate'}
    if 'deployment_strategy' in asddata['service_options'] and asddata['service_options']['deployment_strategy']:
        deployment_strategy = asddata['service_options']['deployment_strategy']
        if deployment_strategy['type'] == 'recreate':
            k8sdeploystrategy = {'type': 'Recreate'}
        elif deployment_strategy['type'] == 'rolling':
            if 'rolling_update' not in k8sdeploystrategy.keys():
                k8sdeploystrategy['rolling_update'] = {}
            if "min_percent" in deployment_strategy.keys():
                k8sdeploystrategy['rolling_update']['max_unavailable'] = f"{deployment_strategy['min_percent']}%"
            if "max_percent" in deployment_strategy.keys():
                k8sdeploystrategy['rolling_update']['max_surge'] = f"{deployment_strategy['max_percent']}%"
    # print(k8sdeploystrategy)

    containers = []
    for container in asddata['containers']:

        asd_service = asddata['service']
        k8scontainer = translate_asd_container_to_k8s_container(container, k8ssecretsbody, k8sconfigslist, asd_service)
        containers.append(k8scontainer)

    # Docs: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
    init_containers = []
    for init_container in asddata.get('init_containers', []):
        asd_service = asddata['service']
        k8scontainer = translate_asd_container_to_k8s_container(init_container, k8ssecretsbody, k8sconfigslist, asd_service, is_init=True)
        init_containers.append(k8scontainer)

    volumes = []
    for shared_volume in asddata.get('shared_volumes', []):
      # Docs: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
      volumes.append({
        'name': shared_volume,
        'emptyDir': {}
      })

    if k8sconfigslist:
        for config in k8sconfigslist:
            volumes.append(
                {
                    'name': config['name'],
                    'configMap': {
                        'name': config['name']
                    }
                }
            )

    arcname = arcade_name.replace("_", "-")

    if volumes:
        k8sdeploypodspec = {'containers': containers, 'initContainers': init_containers, 'volumes': volumes, 'hostNetwork': False,
                            'dnsConfig': {'searches': [arcname]}}
    else:
        k8sdeploypodspec = {'containers': containers, 'initContainers': init_containers, 'hostNetwork': False, 'dnsConfig': {'searches': [arcname]}}

    k8sdeploytemplate = {'spec': k8sdeploypodspec,
                         'metadata': {'labels': labels}}
    k8sdeployselector = {'matchLabels': labels}
    k8sdeployspec = {'replicas': replicas, 'template': k8sdeploytemplate, 'retries': retries,
                     'selector': k8sdeployselector, 'strategy': k8sdeploystrategy}
    k8sdeploybody = {
        'apiVersion': 'apps/v1', 'kind': 'Deployment', 'spec': k8sdeployspec, 'metadata': k8sdeploymeta}

    return k8sdeploybody

def translate_asd_container_to_k8s_container(asd_container, k8ssecretsbody, k8sconfigslist, asd_service, is_init=False):
    """Translate asd_container python object to k8s container python object.

    :param asd_container: ASD container python object
    :return: k8scontainer
    """
    limits = {}
    requests = {}
    if "cpu_limit" in asd_container.keys():
        limits["cpu"] = asd_container["cpu_limit"]
    if "mem_limit" in asd_container.keys():
        limits["memory"] = '{}Mi'.format(asd_container["mem_limit"])
    if "cpu" in asd_container.keys():
        requests["cpu"] = asd_container["cpu"]
    if "mem" in asd_container.keys():
        requests["memory"] = '{}Mi'.format(asd_container["mem"])
    containerresources = {'limits': limits, 'requests': requests}
    container_ports = []

    readiness_probe = get_container_readiness_probe(asd_container, is_init)

    # HACK TO DISABLE HEALTHCHECKS
    # readiness_probe = None

    for port_mapping in asd_container['port_mappings']:
        container_port = {'containerPort': port_mapping['port']}
        container_ports.append(container_port)

    k8s_command = asd_container.get('command', None)

    if k8ssecretsbody:
        if k8sconfigslist:

            volume_mounts = asd_container.get('volume_mounts', [])

            for config in k8sconfigslist:
                volume_mounts.append({'name': config['name'], 'mountPath': config['path']})

            k8scontainer = {
                'name': asd_container['name'],
                'image': asd_container['image'],
                'imagePullPolicy': 'Always',
                'command': k8s_command,
                'envFrom': [
                    {
                        'configMapRef': {
                            'name': asd_service
                        }
                    },
                    {
                        'secretRef': {
                            'name': f"{asd_service}-secrets"
                        }
                    }
                ],
                'ports': container_ports,
                'readinessProbe': readiness_probe,
                'resources': containerresources,
                'volumeMounts': volume_mounts
            }
        else:
            k8scontainer = {
                'name': asd_container['name'],
                'image': asd_container['image'],
                'imagePullPolicy': 'Always',
                'command': k8s_command,
                'volumeMounts': asd_container.get('volume_mounts', []),
                'envFrom': [
                    {
                        'configMapRef': {
                            'name': asd_service
                        }
                    },
                    {
                        'secretRef': {
                            'name': f"{asd_service}-secrets"
                        }
                    }
                ],
                'ports': container_ports,
                'readinessProbe': readiness_probe,
                'resources': containerresources
            }
    else:
        if k8sconfigslist:

            volume_mounts = asd_container.get('volume_mounts', [])

            for config in k8sconfigslist:
                volume_mounts.append({'name': config['name'], 'mountPath': config['path']})

            k8scontainer = {
                'name': asd_container['name'],
                'image': asd_container['image'],
                'imagePullPolicy': 'Always',
                'command': k8s_command,
                'envFrom': [{
                    'configMapRef': {
                        'name': asd_service
                    }
                }],
                'ports': container_ports,
                'readinessProbe': readiness_probe,
                'resources': containerresources,
                'volumeMounts': volume_mounts
            }
        else:
            k8scontainer = {
                'name': asd_container['name'],
                'image': asd_container['image'],
                'imagePullPolicy': 'Always',
                'command': k8s_command,
                'volumeMounts': asd_container.get('volume_mounts', []),
                'envFrom': [{
                    'configMapRef': {
                        'name': asd_service
                    }
                }],
                'ports': container_ports,
                'readinessProbe': readiness_probe,
                'resources': containerresources
            }

    return k8scontainer

def get_container_readiness_probe(asd_container, is_init=False):
    if is_init:
        # initContainers do not support or need readiness probes
        return None
    else:
        readiness_check_path = asd_container.get('readiness_check_path', "/")
        readiness_check_port = asd_container.get('readiness_check_port', 80)
        readiness_check_scheme = "HTTPS" if "readiness_check_https" in asd_container.keys() else "HTTP"
        return {'httpGet': {
            'path': readiness_check_path, 'port': readiness_check_port,
            'scheme': readiness_check_scheme}}


# --------------------------------------------------------------------
#
# translatek8sconfigmap
#
# --------------------------------------------------------------------
def translatek8sconfigmap(asddata):
    """Translate asd python object to k8s configmap python object.

    :param asddata: ASD python object
    :return: k8sconfigmapbody
    """
    labels = {'infrastructure': asddata['service'], 'version': str(asddata['version'])}

    # Add custom tags
    for key, value in asddata['tags'].items():
        labels[key] = value

    # Get each key/val pair for config data
    # Convert keys to uppercase to fit envvar standard
    k8sconfigmapdata = {}
    for key, value in asddata['application_config'].items():
        k8sconfigmapdata[key.upper()] = value

    k8sconfigmapmeta = {'name': asddata['service'], 'labels': labels}
    k8sconfigmapbody = {'apiVersion': "v1",
                        'kind': "ConfigMap",
                        'metadata': k8sconfigmapmeta,
                        'data': k8sconfigmapdata}

    return k8sconfigmapbody


# --------------------------------------------------------------------
#
# translatek8ssecrets
#
# --------------------------------------------------------------------
def translatek8ssecrets(arcade_name, asddata):
    """Query AWS Secrets Manager for any available secrets and translate
    them into a configmap object.

    Secret Path: arcade_name/asteroid_name/service_name/secret-1...n

    :param asddata: ASD python object
    :return: k8ssecretsbody, k8sbinarysecretsbody
    """

    narc_id = asddata['service']
    asteroid_name = narc_id[len('narc-'):narc_id.find('-', narc_id.find('-') + 1)]
    service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]

    # Query secret manager for all key/value pairs
    secret, decoded_binary_secret = get_secret(arcade_name, asteroid_name, service_name)

    k8ssecretsbody = None
    k8sbinarysecretsbody = None

    if secret:
        # Create configmap with the key:value secrets
        labels = {'infrastructure': asddata['service'], 'version': str(asddata['version'])}

        # Add custom tags
        for key, value in asddata['tags'].items():
            labels[key] = value

        # Get each key/val pair for secret data
        # Convert keys to uppercase to fit envvar standard
        k8sconfigmapdata = {}
        for key, value in json.loads(secret).items():

            # Secrets need the data to be base64 encoded to work with envvars
            secret_b64_bytes = base64.b64encode(value.encode("utf-8"))
            secret_b64 = secret_b64_bytes.decode("ascii")

            k8sconfigmapdata[key.upper()] = secret_b64

        k8sconfigmapmeta = {'name': f"{asddata['service']}-secrets", 'labels': labels}
        k8ssecretsbody = {'apiVersion': "v1",
                          'kind': "Secret",
                          'type': "Opaque",
                          'metadata': k8sconfigmapmeta,
                          'data': k8sconfigmapdata}

    if decoded_binary_secret:
        # Create configmap/file mounts for binary secrets
        # TODO: HANDLE BINARY SECRETS LIKE JKS FILES
        pass

    return k8ssecretsbody, k8sbinarysecretsbody


# --------------------------------------------------------------------
#
# translatek8sconfigs
#
# --------------------------------------------------------------------
def translatek8sconfigs(arcade_name, asddata):
    """Query AWS Secrets Manager for any available config file data.
    Put them in a configmap object and mount them on the filesystem
    at the location: /etc/arcade/configs/FILE_NAME

    Secret Path: arcade_name/asteroid_name/service_name/configs/CONFIG_FILE_NAME

    The contents of the config file in Secrets Manager will be Base64

    ;param asddata: ASD python object
    :return: k8sconfigsbody
    """

    narc_id = asddata['service']
    asteroid_name = narc_id[len('narc-'):narc_id.find('-', narc_id.find('-') + 1)]
    service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]

    # Query secret manager for all key/value pairs
    secret, decoded_binary_secret = get_secret(arcade_name, asteroid_name, service_name, True)

    all_configs = _parse_all_configs(secret)

    config_maps = None
    k8sbinaryconfigsbody = None

    if all_configs:

        config_maps = []
        config_num = 1
        # Loop through each path with configs as a configmap will be required for each path
        for path, data in all_configs.items():
            config_name = f"{asddata['service']}-configs{config_num}"
            config = {
                'name': config_name,
                'path': path
            }

            # LABEL CANNOT BE B64 BECAUSE NO = ALLOWED, ONLY . - _
            # Substitute "/" for "slash." to make K8s safe and still allow users to use . - _ in dirnames
            # Note: Label values must begin with alphanumeric
            path_encoded = path.replace("/", "slash.")

            # BUILD CONFIGMAP YAML
            # Create configmap with the key:value secrets
            labels = {'path': path_encoded, 'infrastructure': asddata['service'], 'version': str(asddata['version'])}

            # Add custom tags
            for key, value in asddata['tags'].items():
                labels[key] = value

            # Get each key/val pair for secret data
            k8sconfigmapdata = {}
            for key, value in all_configs[path]:
                try:
                    k8sconfigmapdata[key] = base64.b64decode(value).decode('utf-8')
                except binascii.Error:
                    k8sconfigmapdata[key] = value
                except UnicodeDecodeError:
                    k8sconfigmapdata[key] = value

            k8sconfigmapmeta = {'name': f"{config_name}", 'labels': labels}
            k8sconfigsbody = {'apiVersion': "v1",
                              'kind': "ConfigMap",
                              'metadata': k8sconfigmapmeta,
                              'data': k8sconfigmapdata}

            config['yaml'] = k8sconfigsbody

            # Add config dict to list of all of them
            config_maps.append(config)

            config_num = config_num + 1

    if decoded_binary_secret:
        # Create configmap/file mounts for binary secrets
        # TODO: HANDLE BINARY SECRETS LIKE JKS FILES
        pass

    return config_maps, k8sbinaryconfigsbody


# --------------------------------------------------------------------
#
# get_secret
#
# --------------------------------------------------------------------
def get_secret(arcade_name, asteroid_name, service_name, configs=False):
    if configs:
        secret_name = f"{arcade_name}/{asteroid_name}/{service_name}/configs/"
    else:
        secret_name = f"{arcade_name}/{asteroid_name}/{service_name}/"

    region_name = common.get_arcade_region(arcade_name)

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            logging.error("DecryptionFailureException")
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            logging.error("InternalServiceErrorException")
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            logging.error("InvalidParameterException")
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            # This is a perfectly acceptible outcome.  This happens when a secret is marked for deletion.
            # Treat the secret as though it doesn't exist
            secret = None
            decoded_binary_secret = None
            return secret, decoded_binary_secret
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            # This is a perfectly acceptible outcome as it's possible a service has no secrets!
            secret = None
            decoded_binary_secret = None
            return secret, decoded_binary_secret
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        secret = None
        decoded_binary_secret = None

        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])

        return secret, decoded_binary_secret


# --------------------------------------------------------------------
#
# translatek8sservice
#
# --------------------------------------------------------------------
def translatek8sservice(asddata):
    """Translate asd python object to k8s service python object.

    :param asddata: ASD python object
    :return: k8sservicebody
    """
    labels = {'infrastructure': asddata['service'], 'version': str(asddata['version'])}

    # Add custom tags
    for key, value in asddata['tags'].items():
        labels[key] = value

    if asddata['service_options']['load_balanced']['public'] or \
            asddata['service_options']['load_balanced']['private']:
        k8sserviceloadbalanced = True
    else:
        k8sserviceloadbalanced = False

    if k8sserviceloadbalanced:
        routing_type = "NodePort"
    else:
        routing_type = "ClusterIP"

    k8sserviceports = []
    for container in asddata['containers']:
        for port_mapping in container['port_mappings']:
            service_port = {'port': port_mapping['port'], 'name': port_mapping['port_name']}
            k8sserviceports.append(service_port)

    # Grab just the service shortname (after second "-" until end)
    narc_id = asddata['service']
    short_service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]

    k8sservicemeta = {'name': short_service_name, 'labels': labels}
    k8sservicebody = {'apiVersion': "v1",
                      'kind': "Service",
                      'metadata': k8sservicemeta,
                      'spec': {'type': routing_type,
                               'selector': labels,
                               'ports': k8sserviceports}}

    return k8sservicebody


# --------------------------------------------------------------------
#
# nukeK8s_parallel
#
# --------------------------------------------------------------------
async def nukeK8s_parallel(narcid):
    """Destorys K8s Deployment that is running.

    Args:
        narcid str: the narc id to destroy
    """
    k8s_apps_v1 = client.AppsV1Api()
    k8s_core_v1 = client.CoreV1Api()

    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    # Create short service name by truncating narc_id to everything after the second "-"
    short_service_name = narcid[narcid.find('-', narcid.find('-') + 1) + 1:]

    # Remove the deployment
    try:
        response = k8s_apps_v1.delete_namespaced_deployment(
            name=narcid, namespace=asteroid_name, pretty='false')
        logging.info('Deployment object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the service object
    try:
        delete_service = k8s_core_v1.delete_namespaced_service(
            name=short_service_name, namespace=asteroid_name)
        logging.info('Service object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the configmap for application_config
    try:
        delete_configmap = k8s_core_v1.delete_namespaced_config_map(
            name=narcid, namespace=asteroid_name)
        logging.info('Application Config configmap object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the configmap for Security Manager secrets
    try:
        delete_configmap_secrets = k8s_core_v1.delete_namespaced_config_map(
            name=f"{narcid}-secrets", namespace=asteroid_name)
        logging.info('Security Manager managed secrets configmap object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the secret for Security Manager secrets
    try:
        delete_secret_secrets = k8s_core_v1.delete_namespaced_secret(
            name=f"{narcid}-secrets", namespace=asteroid_name)
        logging.info('Security Manager managed secrets secrets object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the secret for Security Manager secrets
    try:
        delete_secret_secrets = k8s_core_v1.delete_namespaced_secret(
            name=f"{narcid}-secrets", namespace=asteroid_name)
        logging.info('Security Manager managed secrets secrets object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    counter = 1
    # Start at configmap ending configs1 and iterate until we no longer find them
    while True:
        # Remove the configmap for Security Manager config files
        try:
            delete_configmap_configs = k8s_core_v1.delete_namespaced_config_map(
                name=f"{narcid}-configs{counter}", namespace=asteroid_name)
            logging.info(f'Secrets Manager managed files configmap{counter} terminated...')
            counter = counter + 1
        except ApiException as k8serror:
            # 404 is A-OK because it's possible the resource doesn't exist
            # logging.error(k8serror)
            break

    return True


# --------------------------------------------------------------------
#
# nukeK8s_parallel
#
# --------------------------------------------------------------------
def nukeK8s_serial(narcid):
    """Destorys K8s Deployment that is running.

    Args:
        narcid str: the narc id to destroy
    """
    k8s_apps_v1 = client.AppsV1Api()
    k8s_core_v1 = client.CoreV1Api()

    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    # Create short service name by truncating narc_id to everything after the second "-"
    short_service_name = narcid[narcid.find('-', narcid.find('-') + 1) + 1:]

    # Remove the deployment
    try:
        response = k8s_apps_v1.delete_namespaced_deployment(
            name=narcid, namespace=asteroid_name, pretty='false')
        logging.info('Deployment object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the service object
    try:
        delete_service = k8s_core_v1.delete_namespaced_service(
            name=short_service_name, namespace=asteroid_name)
        logging.info('Service object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the configmap for application_config
    try:
        delete_configmap = k8s_core_v1.delete_namespaced_config_map(
            name=narcid, namespace=asteroid_name)
        logging.info('Application Config configmap object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the configmap for Security Manager secrets
    try:
        delete_configmap_secrets = k8s_core_v1.delete_namespaced_config_map(
            name=f"{narcid}-secrets", namespace=asteroid_name)
        logging.info('Security Manager managed secrets configmap object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    # Remove the secret for Security Manager secrets
    try:
        delete_secret_secrets = k8s_core_v1.delete_namespaced_secret(
            name=f"{narcid}-secrets", namespace=asteroid_name)
        logging.info('Security Manager managed secrets secrets object terminated...')
    except ApiException as k8serror:
        # 404 is A-OK because it's possible the resource doesn't exist
        # logging.error(k8serror)
        pass
    counter = 1
    # Start at configmap ending configs1 and iterate until we no longer find them
    while True:
        # Remove the configmap for Security Manager config files
        try:
            delete_configmap_configs = k8s_core_v1.delete_namespaced_config_map(
                name=f"{narcid}-configs{counter}", namespace=asteroid_name)
            logging.info(f'Secrets Manager managed files configmap{counter} terminated...')
            counter = counter + 1
        except ApiException as k8serror:
            # 404 is A-OK because it's possible the resource doesn't exist
            # logging.error(k8serror)
            break

    return True


# --------------------------------------------------------------------
#
# executek8s_parallel
#
# --------------------------------------------------------------------
async def executek8s_parallel(arcade_name, asddata):
    """Translate ASD data and then execute.

    :param asddata: ASD python object
    :return: True if deployment and service succeed
    """
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    k8s.load_arcade_k8s_config(arcade_name)
    k8s_apps_v1 = client.AppsV1Api()
    k8s_core_v1 = client.CoreV1Api()

    k8sconfigmap = translatek8sconfigmap(asddata)
    k8ssecretsbody, k8sbinarysecretsbody = translatek8ssecrets(arcade_name, asddata)
    k8sconfigslist, k8sbinaryconfigsbody = translatek8sconfigs(arcade_name, asddata)

    k8sdeployment = translatek8sdeployment(arcade_name, asddata, k8ssecretsbody, k8sbinarysecretsbody, k8sconfigslist,
                                           k8sbinaryconfigsbody)
    k8sservice = translatek8sservice(asddata)

    logging.info(k8sconfigmap)
    logging.info(yaml.dump(k8sconfigmap, Dumper=NoAliasDumper))
    logging.info(k8sdeployment)
    logging.info(yaml.dump(k8sdeployment, Dumper=NoAliasDumper))
    logging.info(k8sservice)
    logging.info(yaml.dump(k8sservice, Dumper=NoAliasDumper))

    logging.info(f"Creating namespace for asteroid {asteroid_name}")
    _create_namespace(arcade_name, narcid, asteroid_name)

    # Create the kubernetes configmap object (will be mounted as envvars into deployment)
    try:
        response = k8s_core_v1.create_namespaced_config_map(
            body=k8sconfigmap, namespace=asteroid_name, pretty='false'
        )
        logging.info(response)
    except ApiException as k8serror:
        # Exception if resource is already created
        # Log info instead of error because it's handled properly
        # logging.info(k8serror)
        logging.info(f"Configmap for {asteroid_name} already exists.  Continuing...")

    # Create the kubernetes Secrets object for secrets (if secrets exist in secrets manager)
    if k8ssecretsbody:
        try:
            response = k8s_core_v1.create_namespaced_secret(
                body=k8ssecretsbody, namespace=asteroid_name, pretty='false'
            )
            logging.info(response)
        except ApiException as k8serror:
            # Exception if resource is already created
            # Log info instead of error because it's handled properly
            logging.info(f"Configmap for {asteroid_name} secrets already exists.  Continuing...")

            # If the secret object already exists, attempt to update it with current key:vals
            try:
                response = k8s_core_v1.patch_namespaced_secret(name=f"{narcid}-secrets",
                                                               body=k8ssecretsbody,
                                                               namespace=asteroid_name,
                                                               pretty='false')
                logging.info(response)
            except ApiException as k8serror:
                logging.error(k8serror)

    # Create the kubernetes configmap object for configs (if configs exist in secrets manager)
    if k8sconfigslist:
        # Loop through all configmaps and make each one
        for config_map in k8sconfigslist:
            try:
                response = k8s_core_v1.create_namespaced_config_map(
                    body=config_map['yaml'], namespace=asteroid_name, pretty='false'
                )
                logging.info(response)
            except ApiException as k8serror:
                # Exception if resource is already created
                # Log info instead of error because it's handled properly
                logging.info(
                    f"Configmap {config_map['name']} for {asteroid_name} configs already exists.  Continuing...")

                # If the secret object already exists, attempt to update it with current key:vals
                try:
                    response = k8s_core_v1.patch_namespaced_config_map(name=config_map['name'],
                                                                       body=config_map['yaml'],
                                                                       namespace=asteroid_name,
                                                                       pretty='false')
                    logging.info(response)
                except ApiException as k8serror:
                    logging.error(k8serror)

    # Create the kubernetes deployment object
    try:
        response = k8s_apps_v1.create_namespaced_deployment(
            # body=k8sobject, namespace="default", pretty='true', dry_run='All')
            body=k8sdeployment, namespace=asteroid_name, pretty='false')
    except ApiException as k8serror:
        logging.error(k8serror)
        return False
    logging.info(response)

    # Loop to check to see if deployment is operational
    deploymentname = k8sdeployment['metadata']['name']
    configmapname = k8sconfigmap['metadata']['name']
    retries = k8sdeployment['spec']['retries']
    retry = 0
    while retry < retries:
        try:
            read_response = k8s_apps_v1.read_namespaced_deployment_status(
                name=deploymentname, namespace=asteroid_name)
        except ApiException as k8serror:
            logging.error(k8serror)
        logging.info(read_response)
        if read_response.status.available_replicas == k8sdeployment['spec']['replicas']:
            break
        retry += 1
        # print(retry)
        # time.sleep
        await asyncio.sleep(10)
    else:
        # WE HAVE EXCEEDED THE TIMEOUT FOR ALLOWING A SERVICE TO BECOME READY, TEAR IT DOWN!
        logging.error('Timeout exceeded for service to become Ready.  Terminating...')
        await nukeK8s_parallel(narcid)

        return False

    # Create the kubernetes service object
    try:
        core_response = k8s_core_v1.create_namespaced_service(
            body=k8sservice, namespace=asteroid_name, pretty='false')
    except ApiException as k8serror:
        logging.error(k8serror)
        return False
    logging.info(core_response)

    return True


# --------------------------------------------------------------------
#
# executek8s_serial
#
# --------------------------------------------------------------------
def executek8s_serial(arcade_name, asddata):
    """Translate ASD data and then execute.

    :param asddata: ASD python object
    :return: True if deployment and service succeed
    """
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    k8s.load_arcade_k8s_config(arcade_name)
    k8s_apps_v1 = client.AppsV1Api()
    k8s_core_v1 = client.CoreV1Api()

    k8sconfigmap = translatek8sconfigmap(asddata)
    k8ssecretsbody, k8sbinarysecretsbody = translatek8ssecrets(arcade_name, asddata)
    k8sconfigslist, k8sbinaryconfigsbody = translatek8sconfigs(arcade_name, asddata)
    k8sdeployment = translatek8sdeployment(arcade_name, asddata, k8ssecretsbody, k8sbinarysecretsbody, k8sconfigslist,
                                           k8sbinaryconfigsbody)
    k8sservice = translatek8sservice(asddata)

    logging.info(k8sconfigmap)
    logging.info(yaml.dump(k8sconfigmap, Dumper=NoAliasDumper))
    logging.info(k8sdeployment)
    logging.info(yaml.dump(k8sdeployment, Dumper=NoAliasDumper))
    logging.info(k8sservice)
    logging.info(yaml.dump(k8sservice, Dumper=NoAliasDumper))

    logging.info(f"Creating namespace for asteroid {asteroid_name}")
    _create_namespace(arcade_name, narcid, asteroid_name)

    # Create the kubernetes configmap object (will be mounted as envvars into deployment)
    try:
        response = k8s_core_v1.create_namespaced_config_map(
            body=k8sconfigmap, namespace=asteroid_name, pretty='false'
        )
        logging.info(response)
    except ApiException as k8serror:
        # Exception if resource is already created
        # Log info instead of error because it's handled properly
        # logging.info(k8serror)
        logging.info(f"Configmap for {asteroid_name} already exists.  Continuing...")

    # Create the kubernetes configmap object for secrets (if secrets exist in secrets manager)
    if k8ssecretsbody:
        try:
            response = k8s_core_v1.create_namespaced_secret(
                body=k8ssecretsbody, namespace=asteroid_name, pretty='false'
            )
            logging.info(response)
        except ApiException as k8serror:
            # Exception if resource is already created
            # Log info instead of error because it's handled properly
            logging.info(f"Configmap for {asteroid_name} secrets already exists.  Continuing...")

            # If the secret object already exists, attempt to update it with current key:vals
            try:
                response = k8s_core_v1.patch_namespaced_secret(name=f"{narcid}-secrets",
                                                               body=k8ssecretsbody,
                                                               namespace=asteroid_name,
                                                               pretty='false')
                logging.info(response)
            except ApiException as k8serror:
                logging.error(k8serror)

    # Create the kubernetes configmap object for configs (if configs exist in secrets manager)
    if k8sconfigslist:
        # Loop through all configmaps and make each one
        for config_map in k8sconfigslist:
            try:
                response = k8s_core_v1.create_namespaced_config_map(
                    body=config_map['yaml'], namespace=asteroid_name, pretty='false'
                )
                logging.info(response)
            except ApiException as k8serror:
                # Exception if resource is already created
                # Log info instead of error because it's handled properly
                logging.info(
                    f"Configmap {config_map['name']} for {asteroid_name} configs already exists.  Continuing...")

                # If the secret object already exists, attempt to update it with current key:vals
                try:
                    response = k8s_core_v1.patch_namespaced_config_map(name=config_map['name'],
                                                                       body=config_map['yaml'],
                                                                       namespace=asteroid_name,
                                                                       pretty='false')
                    logging.info(response)
                except ApiException as k8serror:
                    logging.error(k8serror)

    # Create the kubernetes deployment object
    try:
        response = k8s_apps_v1.create_namespaced_deployment(
            # body=k8sobject, namespace="default", pretty='true', dry_run='All')
            body=k8sdeployment, namespace=asteroid_name, pretty='false')
    except ApiException as k8serror:
        logging.error(k8serror)
        return False
    logging.info(response)

    # Loop to check to see if deployment is operational
    deploymentname = k8sdeployment['metadata']['name']
    configmapname = k8sconfigmap['metadata']['name']
    retries = k8sdeployment['spec']['retries']
    retry = 0
    while retry < retries:
        try:
            read_response = k8s_apps_v1.read_namespaced_deployment_status(
                name=deploymentname, namespace=asteroid_name)
        except ApiException as k8serror:
            logging.error(k8serror)
        logging.info(read_response)
        if read_response.status.available_replicas == k8sdeployment['spec']['replicas']:
            break
        retry += 1
        # print(retry)
        time.sleep(10)
    else:
        # WE HAVE EXCEEDED THE TIMEOUT FOR ALLOWING A SERVICE TO BECOME READY, TEAR IT DOWN!
        logging.error('Timeout exceeded for service to become Ready.  Terminating...')
        nukeK8s_serial(narcid)

        return False

    # Create the kubernetes service object
    try:
        core_response = k8s_core_v1.create_namespaced_service(
            body=k8sservice, namespace=asteroid_name, pretty='false')
    except ApiException as k8serror:
        logging.error(k8serror)
        return False
    logging.info(core_response)

    return True


# --------------------------------------------------------------------
#
# restartk8s_parallel
#
# --------------------------------------------------------------------
async def restartk8s_parallel(arcade_name, asddata, narcid):
    """
    Inspect the hydrated json and inspect the 'desired_state' field
    and look for the keyword 'restart'
    Args:
        arcade_name: The name of the arcade being targeted
        asddata: ASD python object

    Returns:

    """
    if "desired_state" in asddata:
        if asddata['desired_state'] == "restart":
            # Perform the update by adding an annotation to the deployment
            print(f"Restarting the service {narcid}...")

            deployment = f"narc-{narcid}"
            namespace = deployment[len('narc-'):deployment.find('-', deployment.find('-') + 1)]

            v1_apps = client.AppsV1Api()

            now = datetime.datetime.utcnow()
            now = str(now.isoformat("T") + "Z")
            body = {
                'spec': {
                    'template': {
                        'metadata': {
                            'annotations': {
                                'kubectl.kubernetes.io/restartedAt': now
                            }
                        }
                    }
                }
            }
            try:
                v1_apps.patch_namespaced_deployment(deployment, namespace, body, pretty='true')
            except ApiException as e:
                print(f"Could not restart the service {narcid}: {e}")

            # Remove the restart flag from the hydrated ASD
            asteroid = Asteroid()
            asteroid.clear_desired_state(arcade_name, asddata, narcid)


# --------------------------------------------------------------------
#
# modifyk8s_parallel
#
# --------------------------------------------------------------------
async def modifyk8s_parallel(arcade_name, asddata):
    """
    Compare data in hydrated asd with what is currently live.
    Make zero downtime modifications to running services based off diff
    Args:
        arcade_name: The name of the arcade being targeted
        narcid: The narcid being operated on
        asddata: ASD python object

    Returns: True if deployment and service succeed

    """
    narcid = asddata['service']
    # Asteroid name should be between 'narc-' and the next '-'
    asteroid_name = narcid[len('narc-'):narcid.find('-', narcid.find('-') + 1)]

    print(f"Checking {narcid} in asteroid {asteroid_name} for modification...")

    if _check_deployment_for_modification(asddata):
        print(f"Changes detected for {narcid} in asteroid {asteroid_name} updating service...")

        # Update deployment
        k8s.load_arcade_k8s_config(arcade_name)
        k8s_apps_v1 = client.AppsV1Api()
        k8ssecretsbody, k8sbinarysecretsbody = translatek8ssecrets(arcade_name, asddata)
        k8sconfigsbody, k8sbinaryconfigsbody = translatek8sconfigs(arcade_name, asddata)
        k8sdeployment = translatek8sdeployment(arcade_name, asddata, k8ssecretsbody, k8sbinarysecretsbody,
                                               k8sconfigsbody, k8sbinaryconfigsbody)

        logging.info(k8sdeployment)
        logging.info(yaml.dump(k8sdeployment, Dumper=NoAliasDumper))

        # Update the kubernetes deployment object
        try:
            response = k8s_apps_v1.patch_namespaced_deployment(
                # body=k8sobject, namespace="default", pretty='true', dry_run='All')
                name=narcid, body=k8sdeployment, namespace=asteroid_name, pretty='false')
        except ApiException as k8serror:
            logging.error(k8serror)
            return False
        logging.info(response)

    if _check_configmap_for_modification(asddata):
        print(f"Application config changes detected for {narcid} in asteroid {asteroid_name} updating service...")

        # Update configmap
        k8s.load_arcade_k8s_config(arcade_name)
        k8s_core_v1 = client.CoreV1Api()

        k8sconfigmap = translatek8sconfigmap(asddata)

        logging.info(k8sconfigmap)
        logging.info(yaml.dump(k8sconfigmap, Dumper=NoAliasDumper))

        # Update the kubernetes config_map object
        try:
            response = k8s_core_v1.patch_namespaced_config_map(name=narcid, body=k8sconfigmap, namespace=asteroid_name,
                                                               pretty='false')
            logging.info(response)
        except ApiException as k8serror:
            logging.error(k8serror)
            return False

    # Check secrets for updates
    if _check_secrets_for_modification(arcade_name, asddata):
        print(f"Secrets Manager changes detected for {narcid} in asteroid {asteroid_name} updating service...")

        # Update configmap
        k8s.load_arcade_k8s_config(arcade_name)
        k8s_core_v1 = client.CoreV1Api()

        k8ssecretsbody, k8sbinarysecretsbody = translatek8ssecrets(arcade_name, asddata)

        logging.info(k8ssecretsbody)
        logging.info(yaml.dump(k8ssecretsbody, Dumper=NoAliasDumper))

        # Update the kubernetes config_map object
        if k8ssecretsbody:
            try:
                response = k8s_core_v1.patch_namespaced_secret(name=f"{narcid}-secrets", body=k8ssecretsbody,
                                                                   namespace=asteroid_name, pretty='false')
                logging.info(response)
            except ApiException as k8serror:
                logging.error(k8serror)
                return False

    # Check configs for updates

    counter = 1
    # Start at configmap ending configs1 and iterate until we no longer find them
    while True:
        # Remove the configmap for Security Manager config files
        try:
            if _check_configs_for_modification(arcade_name, asddata, counter):
                print(
                    f"Secrets Manager config changes detected for {narcid} in asteroid {asteroid_name} updating service...")

                k8sconfigslist, k8sbinaryconfigsbody = translatek8sconfigs(arcade_name, asddata)

                # Create the kubernetes configmap object for configs (if configs exist in secrets manager)
                if k8sconfigslist:
                    # Loop through all configmaps and make each one
                    k8s_core_v1 = client.CoreV1Api()
                    for config_map in k8sconfigslist:
                        try:
                            # Check to see if configmap is the correct one to update
                            if config_map['name'] == f"{narcid}-configs{counter}":
                                print(f"Updating configmap {config_map['name']}")
                                response = k8s_core_v1.patch_namespaced_config_map(
                                    name=config_map['name'], body=config_map['yaml'], namespace=asteroid_name, pretty='false'
                                )
                                logging.info(response)
                        except ApiException as k8serror:
                            # Exception if resource is already created
                            # Log info instead of error because it's handled properly
                            logging.info(
                                f"Configmap {config_map['name']} for {asteroid_name} could not be updated...")
                            return False

            counter = counter + 1
        except ApiException as k8serror:
            # 404 is A-OK because it's possible the resource doesn't exist
            # logging.error(k8serror)
            break

    # Check load balancers for updates (Adding/removing a public/private LB)
    narc_ingress.check_loadbalancers_for_modification(arcade_name, asddata)

    # Deep inspect the LB to ensure the details have not changed
    narc_ingress.check_loadbalancers_for_update(arcade_name, asddata)

    return True


# --------------------------------------------------------------------
#
# main
#
# --------------------------------------------------------------------
def main():
    """Parse arguments and passing them into functions."""
    s3_client = boto3.client('s3')
    s3_resource = boto3.resource('s3')

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--file", help="asd file to translate", default="")
    parser.add_argument("-b", "--bucket", help="Target bucket containing file.  default is asd2021",
                        default=os.getenv('ASD_BUCKET', default="asd2021"))
    parser.add_argument(
        "-d", "--delete", help='This flag will delete the deployment.', action="store_true")
    parser.add_argument(
        "-n", "--narcid", help='Narc ID, this should be used with the --delete flag')
    log.add_log_level_argument(parser)
    args = parser.parse_args()
    log.set_log_level(args.verbose)

    filename = args.file
    bucket = args.bucket

    if args.delete:
        if args.narcid:
            nukeK8s(args.narcid)
        else:
            print('You must pass in a NarcID')
            sys.exit(1)
    else:
        asddata = getasdfile(s3_resource, bucket, filename)
        executek8s(asddata)


# --------------------------------------------------------------------
#
# _create_namespace
#
# --------------------------------------------------------------------
def _create_namespace(arcade_name, narcid, asteroid_name):
    """Create K8s namespace for asteroid."""
    k8s.load_arcade_k8s_config(arcade_name)
    k8s_core_v1 = client.CoreV1Api()

    labels = {"app": narcid}
    body = client.V1Namespace()
    body.metadata = client.V1ObjectMeta(name=asteroid_name, labels=labels)
    try:
        response = k8s_core_v1.create_namespace(body, pretty=True)
        return response
    except ApiException as k8serror:
        if k8serror.status == 409:  # Conflict
            logging.info(f"Namespace {asteroid_name} already exists.")
            return True
        else:
            print(f"Exception when calling CoreV1Api->create_namespace for {asteroid_name}")
            print(k8serror)
            sys.exit(1)


# --------------------------------------------------------------------
#
# _check_deployment_for_modification
#
# --------------------------------------------------------------------
def _check_deployment_for_modification(asddata):
    """Compare asddata vs deployment in K8s for any modifications"""
    # Get deployment data from k8s
    deployment_data, service_data = get_k8s_data(asddata)

    retval = False

    # Check replica count
    if asddata['service_options']['desired_count'] != deployment_data.spec.replicas:
        print(
            f"New replica count found!: \n New from ASD: {asddata['service_options']['desired_count']} \n Old from k8s: {deployment_data.spec.replicas}")
        retval = True

    asd_containers = asddata['containers']
    k8s_containers = deployment_data.spec.template.spec.containers

    for asd_container in asd_containers:
        # print(asd_container)

        container_found = "false"
        for k8s_container in k8s_containers:
            # Look for matching container between current container in ASD data vs K8s
            # Have to do this in a loop because we cannot guarantee presentation order
            if asd_container['name'] == k8s_container.name:
                # Container found! continue checking individual components for changes
                #print(k8s_container)
                if asd_container['image'] != k8s_container.image:
                    print(
                        f"New container image found!: \n New from ASD: {asd_container['image']} \n Old from K8s: {k8s_container.image}")
                    retval = True

                if int(asd_container['cpu']) != int(k8s_container.resources.requests['cpu']):
                    print(
                        f"New cpu request found!: \n New from ASD: {asd_container['cpu']} \n Old from K8s: {k8s_container.resources.requests['cpu']}")
                    retval = True

                if int(asd_container['cpu_limit']) != int(k8s_container.resources.limits['cpu']):
                    print(
                        f"New cpu limit found!: \n New from ASD: {asd_container['cpu_limit']} \n Old from K8s: {k8s_container.resources.limits['cpu']}")
                    retval = True

                converted_mem = _convert_memory_units(k8s_container.resources.requests['memory'])
                if int(asd_container['mem']) != converted_mem:
                    print(
                        f"New mem request found!: \n New from ASD: {asd_container['mem']} \n Old from K8s: ({converted_mem}) {k8s_container.resources.requests['memory']}")
                    retval = True

                converted_mem = _convert_memory_units(k8s_container.resources.limits['memory'])
                if int(asd_container['mem_limit']) != converted_mem:
                    print(
                        f"New mem limit found!: \n New from ASD: {asd_container['mem_limit']} \n Old from K8s: ({converted_mem}) {k8s_container.resources.limits['memory']}")
                    retval = True

                # Handle k8s deployments with no healthcheck info
                readiness_check_path = None
                readiness_check_port = None
                readiness_check_scheme = None

                if k8s_container.readiness_probe:
                    readiness_check_path = k8s_container.readiness_probe.http_get.path
                    readiness_check_port = k8s_container.readiness_probe.http_get.port
                    readiness_check_scheme = k8s_container.readiness_probe.http_get.scheme

                if asd_container['readiness_check_path'] != readiness_check_path:
                    print(f"New healthcheck path found: path {asd_container['readiness_check_path']} will replace path {readiness_check_path}")
                    retval = True

                # Handle optional field
                hydrated_port = 80
                if "readiness_check_port" in asd_container:
                    hydrated_port = asd_container['readiness_check_port']

                if hydrated_port != readiness_check_port:
                    print(f"New healthcheck port found: port {hydrated_port} will replace port {readiness_check_port}")
                    retval = True

                hydrated_scheme = "HTTP"
                if "readiness_check_https" in asd_container:
                    if asd_container['readiness_check_https']:
                        hydrated_scheme = "HTTPS"

                if hydrated_scheme != readiness_check_scheme:
                    print(f"New healthcheck scheme found: scheme {hydrated_scheme} will replace scheme {readiness_check_scheme}")
                    retval = True

                # Check port lists for modifications
                for asd_port in asd_container['port_mappings']:
                    port_found = False
                    for k8s_port in k8s_container.ports:
                        if asd_port['port'] == k8s_port.container_port:
                            port_found = True

                    if not port_found:
                        print(f"New port found!: The port defined in ASD {asd_port['port']} was not discovered in K8s")
                        retval = True

                container_found = True

        if not container_found:
            # If in all of the K8s data there is no discovered container than we know it's a new container
            # and therefore there is a modification
            retval = True

    return retval


# --------------------------------------------------------------------
#
# _check_configmap_for_modification
#
# --------------------------------------------------------------------
def _check_configmap_for_modification(asddata):
    """Compare asddata's application_config section vs the configmap in K8s for changes"""
    # Get configmap data from k8s
    configmap_data = get_k8s_configmap(asddata)

    if configmap_data:
        for key, val in asddata['application_config'].items():
            if key.upper() in configmap_data.data:
                if val != configmap_data.data[key.upper()]:
                    print(f"Found new value {val} for application config {key}, updating configmap...")
                    return True
            else:
                print(f"Found new application config {key}, updating configmap...")
                return True
    else:
        print(f"Adding configmap data...")
        return True

    return False


# --------------------------------------------------------------------
#
# _check_secrets_for_modification
#
# --------------------------------------------------------------------
def _check_secrets_for_modification(arcade_name, asddata):
    """Compare secrets manager contents vs the configmap in K8s for changes"""
    secrets_data = get_k8s_secrets(asddata)

    narc_id = asddata['service']
    asteroid_name = narc_id[len('narc-'):narc_id.find('-', narc_id.find('-') + 1)]
    service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]

    # Query secret manager for all key/value pairs
    secret, decoded_binary_secret = get_secret(arcade_name, asteroid_name, service_name)

    if secrets_data and secret:
        for key, val in json.loads(secret).items():
            if key.upper() in secrets_data.data:
                if val != base64.b64decode(secrets_data.data[key.upper()]).decode("ascii"):
                    print(f"Found new value for secret manager secret {key}, updating secrets configmap...")
                    return True
            else:
                print(f"Found new secrets config {key}, updating secrets configmap...")
                return True
    # else:
    #    print(f"Adding secrets configmap data...")
    #    return True

    return False


# --------------------------------------------------------------------
#
# _check_configs_for_modification
#
# --------------------------------------------------------------------
def _check_configs_for_modification(arcade_name, asddata, num_configmap):
    """Compare secrets manager contents for config files vs the configmap in K8s for changes"""
    secrets_data = get_k8s_configs(asddata, num_configmap)

    narc_id = asddata['service']
    asteroid_name = narc_id[len('narc-'):narc_id.find('-', narc_id.find('-') + 1)]
    service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]

    # Query secret manager for all key/value pairs
    secret, decoded_binary_secret = get_secret(arcade_name, asteroid_name, service_name, True)
    all_configs = _parse_all_configs(secret)

    # Verify we have secrets data from secrets manager as well as
    if secrets_data and all_configs:
        # Loop through all secrets from Secrets Manager to verify they exist in configmap
        for path, data in all_configs.items():
            # Compare path to ensure we are validating the correct configmap
            if secrets_data.metadata.labels['path'].replace('slash.', '/') == path:
                # Check configmap data for secrets manager entry
                for single_config in data:
                    # Validate whether or not config item exists (name check)
                    if single_config[0] in secrets_data.data:
                        # Key exists!  Check value
                        if secrets_data.data[single_config[0]] != base64.b64decode(single_config[1]).decode('utf-8'):
                            print(f"Found new config value for {single_config[0]}, updating configmap...")
                            return True
                    else:
                        # Key doesn't exist!
                        print(f"Found new config named {single_config[0]}, updating configmap...")
                        return True
        return False  # Nothing failed so everything checks out!
    else:
        print(f"Found new config, updating configmap...")
        return True


# --------------------------------------------------------------------
#
# _convert_memory_units
#
# --------------------------------------------------------------------
def _convert_memory_units(memory):
    """ Will take memory in format such as 512Mi or 1Gi and convert it to an integer representing MB"""
    regex = re.compile("([0-9]+)([a-zA-Z]+)")
    split_tuple = regex.match(memory).groups()

    mem_comp = 0
    if 'Mi' == split_tuple[1]:
        mem_comp = int(split_tuple[0])
    elif 'Gi' == split_tuple[1]:
        mem_comp = int(split_tuple[0]) * 1024
    else:
        print(
            f"ERROR: When comparing memory request in K8s {memory}, units were neither Mi nor Gi")

    return mem_comp


# --------------------------------------------------------------------
#
# _parse_all_configs
#
# --------------------------------------------------------------------
def _parse_all_configs(secrets):
    """
    Will take config file data from secrets manager, parse out PATH data and build/return datastructure
    Returns: {
              STR(PATH) = [
                          [filename, contents],
                          [filename, contents],
                          [filename, contents]
                          ]
             }
    """
    all_configs = {}

    if secrets:

        for key, value in json.loads(secrets).items():
            # Check for specified path by looking for delimiter ':'
            if key.find(':') > -1:
                # Separate path and filename
                name_path = key.split(':')

                filename = name_path[0]
                path = name_path[1]

                # For consistency (because we need to build a dict based on path to group like paths) remove trailing slash if exists
                if path[-1:] == '/':
                    path = path[:-1]

                if path in all_configs:
                    all_configs[path].append([filename, value])
                else:
                    all_configs[path] = []
                    all_configs[path].append([filename, value])

            # By default path will be /etc/arcade/configs/
            else:
                filename = key
                path = "/etc/arcade/configs"

                if path in all_configs:
                    all_configs[path].append([filename, value])
                else:
                    all_configs[path] = []
                    all_configs[path].append([filename, value])

    return all_configs


if __name__ == "__main__":
    main()
