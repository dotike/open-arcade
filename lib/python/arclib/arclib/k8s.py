# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
k8s --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import logging
import os
import re
import yaml
import pprint

from arclib import common
from kubernetes import client, config
from kubernetes.client.rest import ApiException


# --------------------------------------------------------------------
#
# get_asteroid_running_services
#
# --------------------------------------------------------------------
def get_asteroid_running_services(asteroid_name):
    """
    Query K8s for an asteroid running services

    Args:

    Returns:

    """
    k8s_apps_v1 = client.AppsV1Api()
    try:
        deployment_list = k8s_apps_v1.list_deployment_for_all_namespaces(timeout_seconds=10)

        asteroid_deployments = []
        if hasattr(deployment_list, "items"):
            # Filter only narc asteroid deployments
            for deployment in deployment_list.items:
                if re.search(f"^narc-{asteroid_name}-", deployment.metadata.name):
                    asteroid_deployments.append(deployment)

        return asteroid_deployments

    except ApiException as e:
        logging.error(f"Exception when calling AppsV1Api->list_deployment_for_all_namespaces: {e}")
        return []


# --------------------------------------------------------------------
#
# load_arcade_k8s_config
#
# --------------------------------------------------------------------
def load_arcade_k8s_config(arcade_name: str):
    """
    Args:

    Returns:

    """

    cluster_name = f"asteroids-{arcade_name.replace('.', '-')}"
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    # find EKSAdminRole ARN for use with kubernetes config
    iam_client = arcade_session.client('iam')
    role_res = iam_client.get_role(RoleName="EKSAdminRole")
    eksadminrolearn = role_res['Role']['Arn']
    # print("----EKS Admin Role ARN----")
    # print(eksadminrolearn)

    # get EKS cluster information for use in kubernetes config
    eks = arcade_session.client('eks')
    response = eks.describe_cluster(name=cluster_name)

    # print(f"----Describe cluster: {cluster_name}----")
    # pprint.pprint(response)

    context_cert_data = response["cluster"]["certificateAuthority"]["data"]
    context_server = response["cluster"]["endpoint"]
    context_arn = response["cluster"]["arn"]
    context_name = response["cluster"]["name"]
    context_region = context_arn.split(":")[3]

    # print("----Context region----")
    # print(context_region)

    config_dict_yaml = f"""
apiVersion: v1
kind: Config
preferences: {{}}
current-context: {context_name}
clusters:
- cluster:
    certificate-authority-data: {context_cert_data}
    server: {context_server}
  name: {context_arn}
contexts:
- context:
    cluster: {context_arn}
    user: {context_arn}
  name: {context_name}
users:
- name: {context_arn}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws
      args:
      - --region
      - {context_region}
      - eks
      - get-token
      - --cluster-name
      - {context_name}
      - --role-arn
      - {eksadminrolearn}
"""

    # print("----Config yaml----")
    # print(config_dict_yaml)
    tmp_dir = os.getenv("ATMP", '/tmp')
    context_file_name = f"{tmp_dir}/context.yaml"
    with open(context_file_name, "w") as context_file:
        context_file.write(config_dict_yaml)
    # config_dict = yaml.safe_load(config_dict_yaml)
    # print("----Config dict----")
    # pprint.pprint(config_dict)

    # print("----kube config----")
    # load kubernetes config
    # print(config.load_kube_config(config_file=context_file_name))
    return config.load_kube_config(config_file=context_file_name)
