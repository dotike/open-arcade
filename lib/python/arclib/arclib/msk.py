# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
msk --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import base64
import boto3
import logging
import string
import random
import time
import yaml
import botocore.exceptions

from arclib import grv, common
from botocore.exceptions import ClientError


# --------------------------------------------------------------------
#
# get_msk_status
#
# --------------------------------------------------------------------
def get_msk_status(cluster_name: str) -> dict:
    """
    Return the status of a MSK cluster.

    Args:
        cluster_name: cluster name

    Returns:
        status dict of the response or exception dict
    """
    client = boto3.client('kafka')
    response = client.list_clusters(ClusterNameFilter=cluster_name)
    if not response['ClusterInfoList']:
        return {}
    logging.debug(response['ClusterInfoList'])
    
    return response['ClusterInfoList'][0]
    # End of get_msk_status


# --------------------------------------------------------------------
#
# get_msk_info
#
# --------------------------------------------------------------------
def get_msk_info(cluster_name: str) -> dict:
    """
    Return the status of a MSK cluster.

    Args:
        cluster_name: cluster name

    Returns:
        status dict of the response or exception dict
    """
    msk_client = boto3.client('kafka')
    response = msk_client.list_clusters(ClusterNameFilter=cluster_name)
    if not response['ClusterInfoList']:
        return {}
    logging.debug(response['ClusterInfoList'])
    cluster_info = response['ClusterInfoList'][0]
    cluster_arn = cluster_info['ClusterArn']
    if cluster_info['State'] == 'ACTIVE':
        cluster_info.update(msk_client.get_bootstrap_brokers(ClusterArn=cluster_arn))
    return cluster_info
    #


# --------------------------------------------------------------------
#
# get_msk_configuration
#
# --------------------------------------------------------------------
def get_msk_configuration(cluster_name: str) -> dict:
    """
    Return the status of a MSK configuration.

    Args:
        cluster_name: the name of the cluster

    Returns:
        status dict of the response or empty dict
    """
    if not cluster_name:
        return {}

    client = boto3.client('kafka')
    response = client.list_configurations()

    for configuration in response['Configurations']:
        if configuration['Name'].endswith(cluster_name):
            return configuration
        
    return {}
    # End of get_msk_configuration
    

# --------------------------------------------------------------------
#
# create_msk
#
# --------------------------------------------------------------------
def create_msk(cluster_prefix: str,
               gravitar: str,
               instance_type: str,
               brokers_per_az: int,
               ebs_size: int,
               kafka_version: str = '2.6.2') -> dict:
    """
    Create an MSK cluster.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        instance_type: kafka instance type kafka.m5.large
        brokers_per_az: brokers per az
        ebs_size: size of the ebs volume per broker
        kafka_version: kafka version. Defaults to '2.6.2'.

    Returns:
        status dict of the response or exception dict
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"

    status = get_msk_status(msk_name)

    if not status:
        # Create the cluster when it does not exist.
        msk_sg_name = f"{cluster_prefix}_msk.{gravitar}"

        vpc_id = grv.get_vpc_id(gravitar)
        msk_sg_id = grv.check_if_sg(msk_sg_name)
        if not msk_sg_id:
            msk_sg_id = grv.create_grv_sg(sg_name=msk_sg_name, vpc_id=vpc_id)

        client = boto3.client('kafka')

        core_subnets = grv.find_grv_subnets(gravitar, "core")
        number_of_brokers = len(core_subnets) * brokers_per_az
        msk_config = get_msk_configuration(msk_name)
        if not msk_config:
            return msk_config
        msk_config_arn = msk_config['Arn']
        msk_config_rev = msk_config['LatestRevision']['Revision']
        print(f'Creating MSK cluster {msk_name}...')
        status = client.create_cluster(
            BrokerNodeGroupInfo={
                'BrokerAZDistribution': 'DEFAULT',
                'ClientSubnets': core_subnets,
                'InstanceType': 'kafka.m5.large',
                'StorageInfo': {
                    'EbsStorageInfo': {
                        'VolumeSize': ebs_size
                    }
                },
                'SecurityGroups': [msk_sg_id]
            },
            ClusterName=msk_name,
            ConfigurationInfo={
                'Arn': msk_config_arn,
                'Revision': msk_config_rev
            },
            EncryptionInfo={
                'EncryptionInTransit': {
                    'ClientBroker': 'TLS_PLAINTEXT',
                    'InCluster': True
                }
            },
            EnhancedMonitoring='PER_TOPIC_PER_BROKER',
            KafkaVersion=kafka_version,
            NumberOfBrokerNodes=number_of_brokers,
            Tags={
                'grv_name': gravitar,
            }
        )

        while 'CREATING' == status['State']:
            print(f'Waiting for the MSK cluster {msk_name} to be active.')
            time.sleep(120)
            status = get_msk_status(msk_name)

        print(f"Cluster {msk_name} is created!")
        return status
    elif 'CREATING' == status['State']:
        while 'CREATING' == status['State']:
            print(f'Waiting for the MSK cluster {msk_name} to be active.')
            time.sleep(120)
            status = get_msk_status(msk_name)
        return status
    else:
        print(f'MSK cluster {msk_name} already exists, status: {status["State"]}')
        return status

    # Emd of create_msk


# --------------------------------------------------------------------
#
# create_msk_configuration
#
# --------------------------------------------------------------------
def create_msk_configuration(cluster_prefix: str,
                             gravitar: str,
                             kafka_version: str,
                             server_properties: str) -> dict:
    """
    Create an MSK configuration for the MSK cluster, if it doesn't already exist.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        kafka_version: version of kafka for this configuration
        server_properties: kafka options

    Returns:
        status dict of the response or get
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"

    status = get_msk_configuration(msk_name)

    if not status:
        msk_client = boto3.client('kafka')
        print(f'Creating MSK configuration {msk_name}...')
        status = msk_client.create_configuration(
            Description=f"Configuration for {msk_name}",
            KafkaVersions=[
                kafka_version,
            ],
            Name=msk_name,
            ServerProperties=server_properties
        )

    return status
    # End of create_msk_configuration


# --------------------------------------------------------------------
#
# delete_msk
#
# --------------------------------------------------------------------
def delete_msk(cluster_prefix: str,
               gravitar: str) -> dict:
    """
    Delete MSK cluster with given cluster prefix.

    Args:
        cluster_prefix: name of the msk to be deleted
        gravitar: name of gravitar

    Returns:
        empty dict if deletion happens otherwise status is returned
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"
    msk_sg_name = f"{cluster_prefix}_msk.{gravitar}"

    status = get_msk_status(msk_name)

    if not status:
        grv.delete_grv_sg(msk_sg_name)
        return status

    if status and 'DELETING' == status['State']:
        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk cluster {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_status(msk_name)
    else:
        client = boto3.client('kafka')
        print(f'Deleting msk cluster {msk_name}...')
        msk_arn = status['ClusterArn']
        status = client.delete_cluster(ClusterArn=msk_arn)

        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk cluster {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_status(msk_name)

    grv.delete_grv_sg(msk_sg_name)
    
    return status
    # End of delete_msk


# --------------------------------------------------------------------
#
# delete_msk_configuration
#
# --------------------------------------------------------------------
def delete_msk_configuration(cluster_prefix: str,
                             gravitar: str) -> dict:
    """
    Delete msk nodegroup for the cluster.

    Args:
        cluster_prefix: the prefix of cluster
        gravitar: the name of gravitar

    Returns:
        empty dict if deletion happens otherwise status is returned
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"

    status = get_msk_configuration(msk_name)

    if not status:
        return status

    if status and 'DELETING' == status['State']:
        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk configuration {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_configuration(msk_name)
            logging.debug(status)
    else:
        msk_client = boto3.client('kafka')
        msk_config_arn = status['Arn']
        status = msk_client.delete_configuration(Arn=msk_config_arn)

        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk configuration {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_configuration(msk_name)
            logging.debug(status)

    logging.debug(status)

    return status
    # End of delete_msk_configuration


# --------------------------------------------------------------------
#
# _id_generator
#
# --------------------------------------------------------------------
def _id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
    # End of _id_generator


# --------------------------------------------------------------------
#
# _delete_dns_records
#
# --------------------------------------------------------------------
def _delete_dns_records(arcadeName):
    """
    Delete CNAMEs and HealthChecks

    Args:
        Dict containing data

    Returns:
        A return code 0 == OK, 1 == Not OK
    """
    client = boto3.client('route53')

    returnCode = 0

    hostedZoneId = grv.tld_to_zone_id(arcadeName)

    response = client.list_resource_record_sets(
        HostedZoneId=hostedZoneId)

    ResourceRecords = response['ResourceRecordSets']
    for entry in ResourceRecords:
        recordType = entry['Type']
        if recordType == 'CNAME':
            recordName = entry['Name']
            if 'kafka' in recordName or 'zookeeper' in recordName:
                setIdentifier = entry['SetIdentifier']
                ttl = entry['TTL']
                weight = entry['Weight']
                healthCheckId = entry['HealthCheckId']
                value = entry['ResourceRecords'][0]['Value']

                response = client.change_resource_record_sets(
                    HostedZoneId=hostedZoneId,
                    ChangeBatch={
                        'Changes': [
                            {
                                'Action': 'DELETE',
                                'ResourceRecordSet': {
                                    'Name': recordName,
                                    'Type': 'CNAME',
                                    'SetIdentifier': setIdentifier,
                                    'Weight': weight,
                                    'TTL': ttl,
                                    'ResourceRecords': [
                                        { 'Value': value },
                                        ],
                                    'HealthCheckId': healthCheckId
                                    }
                                },
                            ]
                        }
                    )
                # End of function call
            # End of if
        # End of if
    # End of for loop

    return returnCode
    # End of _delete_dns_records


# --------------------------------------------------------------------
#
# _create_health_check
#
# --------------------------------------------------------------------
def _create_health_check(p_dict):
    """
    Create health checks for a MSK CNAME.

    Args:
        p_dict: dict containing data nessary to create the health checks

    Returns:
        r_dict: dict containg status and return data

    """
    RS = common.ReturnStatus()
    r_dict = common.gen_return_dict('In _create_health_check')

    connStrings = p_dict['connStrings']
    arcadeName  = p_dict['arcadeName']
    serviceName = p_dict['serviceName']
    hostName    = p_dict['hostName']
    region      = p_dict['region']

    returnStatus = 0
    HealthChecksIds = []
    r53_client = boto3.client('route53')

    try:
        response = r53_client.list_health_checks()
    except (Route53.Client.exceptions.InvalidInput,
            Route53.Client.exceptions.IncompatibleVersion) as err:
        r_dict['status'] = RS.FAIL
        r_dict['msg'] = 'Error list_health_checks failed'
        r_dict['msg'] = err

    if r_dict['status'] == RS.OK:
        tmpStr = p_dict['arcadeName'].replace('.arc', '')

        for entry in connStrings:
            #
            # Yes, I know this is stupid but this is to get around
            # the fact that deleting a health check is not REALLY
            # deleted. Boto3 and the console say its gone but what
            # is really going on is the removal is scheduled for
            # the next time garbage collection runs. It would be nice
            # if this sort of operation was atomic but who am I
            # going to talk to about this.
            #
            suffix = _id_generator()
            callerReference = f"{tmpStr}_health_check_{suffix}"
            healthCheckName = callerReference

            try:
                response = r53_client.create_health_check(
                    CallerReference=callerReference,
                    HealthCheckConfig={
                        'Port': 53,
                        'Type': 'TCP',
                        'FullyQualifiedDomainName': hostName,
                        'RequestInterval': 30,
                        'FailureThreshold': 2
                        }
                    )
            except (Route53.Client.exceptions.TooManyHealthChecks,
                    Route53.Client.exceptions.HealthCheckAlreadyExists,
                    Route53.Client.exceptions.InvalidInput) as err:
                r_dict = common.gen_return_dict("ERROR: caught an exception")
                r_dict['status'] = RS.FAIL
                r_dict['data'] = err
                break
            # End of try block

            if r_dict['status'] == RS.OK:
                healthCheckId = response['HealthCheck']['Id']
                p_dict['healthCheckId'] = healthCheckId

                try:
                    response = r53_client.change_tags_for_resource(
                        ResourceType='healthcheck',
                        ResourceId=healthCheckId,
                        AddTags=[
                            {
                                'Key': 'Name',
                                'Value': healthCheckName
                                },
                            ]
                        )
                except (Route53.Client.exceptions.InvalidInput,
                        Route53.Client.exceptions.NoSuchHealthCheck,
                        Route53.Client.exceptions.NoSuchHostedZone,
                        Route53.Client.exceptions.PriorRequestNotComplete,
                        Route53.Client.exceptions.ThrottlingException) as err:
                    r_dict = common.gen_return_dict("ERROR: caught an exception")
                    r_dict['status'] = RS.FAIL
                    r_dict['data'] = err
                    break
                # End of try block

                HealthChecksIds.append(healthCheckId)
            # End of if
        # End of for loop
        r_dict['data'] = HealthChecksIds
    # End of if

    return r_dict
    # End of _create_health_check


# --------------------------------------------------------------------
#
# _add_dns_record
#
# --------------------------------------------------------------------
def _add_dns_record(p_dict: dict) -> dict:
    """
    Create CNAMEs for kafka and zookeeper

    Args:
        Dict containing data

    Returns:
        A return code 0 == OK, 1 == Not OK
    """
    connStrings = p_dict['connStrings']
    arcadeName  = p_dict['arcadeName']
    serviceName = p_dict['serviceName']
    entry_index = p_dict['entry_index']

    domainName = arcadeName.replace('_', '-')

    client = boto3.client('route53')
    hostedZone = grv.tld_to_zone_id(arcadeName)
    
    hostName = f"{serviceName}.{domainName}"
    p_dict['hostName'] = hostName

    r_dict = _create_health_check(p_dict)
    health_check_ids = r_dict['data']

    for index in range(len(connStrings)):
        entry_index += 1
        connStrName = connStrings[index].split(':')[0]
        
        health_check_id = health_check_ids[index]
        setId = f"Entry-{entry_index:02d}"

        try:
            response = client.change_resource_record_sets(
                HostedZoneId=hostedZone,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'CREATE',
                            'ResourceRecordSet': {
                                'Name': hostName.replace('_', '-'),
                                'Type': 'CNAME',
                                'Weight': 85,
                                'TTL': 15,
                                'HealthCheckId': health_check_id,
                                'SetIdentifier': setId,
                                'ResourceRecords': [
                                    { 'Value': connStrName.replace('_', '-') },
                                    ]
                                }
                            }
                        ]
                    }
                )
        except (Route53.Client.exceptions.NoSuchHostedZone,
                Route53.Client.exceptions.NoSuchHealthCheck,
                Route53.Client.exceptions.InvalidChangeBatch,
                Route53.Client.exceptions.InvalidInput,
                Route53.Client.exceptions.PriorRequestNotComplete) as err:
            r_dict = common.gen_return_dict("ERROR: caught an exception")
            r_dict['status'] = RS.FAIL
            r_dict['data'] = err

    # End of for loop

    r_dict['entry_index'] = entry_index

    return r_dict
    # End of _add_dns_record


# --------------------------------------------------------------------
#
# create_msk_route53_record
#
# --------------------------------------------------------------------
def create_msk_route53_records(arcade_name: str) -> dict:
    """
    Create CNAMEs and HealthChecks for kafka and zookeeper

    Args:
        Dict containing data

    Returns:
        A return code 0 == OK, 1 == Not OK
    """
    p_dict = {}
    p_dict['arcadeName'] = arcade_name
    cluster = ''
    debug = False

    RS = common.ReturnStatus()
    r_dict = count_cnames(arcade_name)
    entry_index = r_dict['data']

    r_dict = common.gen_return_dict('In create_msk_route53_redord')

    cluster_name  = arcade_name.replace('_', '').replace('.', '-')
    cluster_name = f"asteroids-{cluster_name}"
    p_dict['clusterName'] = cluster_name

    client = boto3.client('kafka')

    status_dict = get_msk_status(cluster_name)
    if status_dict['State'] == 'ACTIVE':
        try:
            Response = client.list_clusters()
            ClusterInfo = Response['ClusterInfoList']
        except (Kafka.Client.exceptions.BadRequestException,
                Kafka.Client.exceptions.InternalServerErrorException,
                Kafka.Client.exceptions.UnauthorizedException,
                Kafka.Client.exceptions.ForbiddenException) as err:
            r_dict['status'] = RS.FAIL
            r_dict['data'] = err
            r_dict['msg'] = 'Error failed to list clusters'
        # End of try block

        if r_dict['status'] == RS.OK:
            for entry in ClusterInfo:
                if entry['ClusterName'] == cluster_name:
                    cluster = entry
                    break
            # End of for loop

            clusterArn = cluster['ClusterArn']
            clusterBits = clusterArn.split(':')
            region = clusterBits[3]
            p_dict['region'] = region

            connString = ""
            Services = ['zookeeper', 'kafka']
            for service in Services:
                if service == 'zookeeper':
                    # zookeeper
                    try:
                        Response = client.describe_cluster(ClusterArn=clusterArn)
                        ci = Response['ClusterInfo']
                        zookeeperConnectString    = ci['ZookeeperConnectString']
                        connStrings = zookeeperConnectString.split(',')
                    except (Kafka.Client.exceptions.NotFoundException,
                            Kafka.Client.exceptions.BadRequestException,
                            Kafka.Client.exceptions.UnauthorizedException,
                            Kafka.Client.exceptions.InternalServerErrorException,
                            Kafka.Client.exceptions.ForbiddenException) as err:
                        r_dict['status'] = RS.FAIL
                        r_dict['msg'] = 'Error describe_cluster failed'
                        r_dict['data'] = err
                        break
                    # End of try block
                else:
                    # kafka
                    try:
                        Response = client.get_bootstrap_brokers(ClusterArn=clusterArn)
                        bootstrapBrokerString = Response['BootstrapBrokerStringTls']
                        connStrings = bootstrapBrokerString.split(',')
                    except (Kafka.Client.exceptions.BadRequestException,
                            Kafka.Client.exceptions.UnauthorizedException,
                            Kafka.Client.exceptions.InternalServerErrorException,
                            Kafka.Client.exceptions.ConflictException,
                            Kafka.Client.exceptions.ForbiddenException) as err:
                        r_dict['status'] = RS.FAIL
                        r_dict['msg'] = 'Error get_bootstrap_brokers failed'
                        r_dict['data'] = err
                        break
                    # End of try block
                # End of if/else

                if r_dict['status'] == RS.OK:
                    #connString = connStrings
                    entry_index += 1
                        
                    p_dict['entry_index'] = entry_index
                    p_dict['connStrings'] = connStrings
                    p_dict['serviceName'] = service
                        
                    r_dict = _add_dns_record(p_dict)
                    entry_index = r_dict['entry_index']
                    entry_index += 1
                    # End of for loop
                else:
                    break
                # End of if/else
            # End of for loop
        # End of for loop
    # End of if

    return r_dict
    # End of create_msk_route53_records


# --------------------------------------------------------------------
#
# delete_msk_route53_records
#
# --------------------------------------------------------------------
def delete_msk_route53_records(arcade_name):
    """
    This is the driving function to delete CNAMEs and HealthChaecks
    for kafka and zookeeper

    Args:
        arcade_name: The fully quantified arcade name

    Returns:
        A return code 0 == OK, 1 == Not OK
    """
    RS = common.ReturnStatus()

    r_dict = common.gen_return_dict("Delete MSK Route 53 Records")

    r_dict = delete_msk_dns_records(arcade_name)

    if r_dict['status'] == RS.OK:
        r_dict = delete_msk_health_checks(arcade_name)

    if r_dict['status'] == RS.OK:
        r_dict['msg'] = 'CNAME for zookeeper and kafka deletes'
    else:
        r_dict['msg'] = 'ERROR CNAME for zookeeper and kafka NOT deletes'

    return r_dict
    # End of delete_msk_route53_records


# --------------------------------------------------------------------
#
# _delete_health_checks
#
# --------------------------------------------------------------------
def _delete_health_checks(arcadeName: str) -> dict:
    """
    Delete HealthChecks

    Args:
        Dict containing data

    Returns:
        A return code 0 == OK, 1 == Not OK
    """

    r_dict = common.gen_return_dist('In delete_health_chacks')

    arcadeName = arcadeName.replace('.arc', '')
    r53_client = boto3.client('route53')

    returnCode = 0

    try:
        response = r53_client.list_health_checks()
        HealthChecks = response['HealthChecks']
    except (Route53.Client.exceptions.InvalidInput,
            Route53.Client.exceptions.IncompatibleVersion) as err:
        r_dict['status'] = ES.FAIL
        r_dict['data'] = err
        r_dict['msg'] = 'Error list_health_checks failed'

    if r_dict['status'] == RS.OK:
        for entry in HealthChecks:
            callerReference = entry['CallerReference']
            if arcadeName in callerReference:
                healthCheckId = entry['Id']

                try:
                    response = r53_client.delete_health_check(
                        HealthCheckId = healthCheckId)
                except (Route53.Client.exceptions.NoSuchHealthCheck,
                        Route53.Client.exceptions.HealthCheckInUse,
                        Route53.Client.exceptions.InvalidInput) as err:
                    r_dict = common.gen_return_dict("ERROR: caught an exception")
                    r_dict['status'] = RS.FAIL
                    r_dict['data'] = err
                    break
                # try block
            # end of if
        # end of for loop
    # End of if

    return r_dict
    # End of _delete_health_checks


# --------------------------------------------------------------------
#
# _find_cnames
#
# --------------------------------------------------------------------
def _find_cnames(arcade_name:str) -> dict:
    """
    """

    RS = common.ReturnStatus()

    cname_list = []
    cname_found = False
    
    r_dict = common.gen_return_dict("In _find_cnames")

    hosted_zone_id = grv.tld_to_zone_id(arcade_name)

    # CNAMEs
    try:
        r53_client = boto3.client('route53')
        response = r53_client.list_resource_record_sets(
            HostedZoneId=hosted_zone_id)
    except (Route53.Client.exceptions.NoSuchHostedZone,
            Route53.Client.exceptions.InvalidInput) as err:
        r_dict = common.gen_return_dict("ERROR: caught an exception")
        r_dict['status'] = RS.FAIL
        r_dict['data'] = err

    if r_dict['status'] == RS.OK:
        ResourceRecords = response['ResourceRecordSets']
        for entry in ResourceRecords:
            recordType = entry['Type']
            if recordType == 'CNAME':
                cname_found = True
                recordName = entry['Name']
                cname_list.append(entry)
            # End of if
        # End of for loop

        if cname_found:
            r_dict['status'] = RS.OK
            r_dict['msg'] = "CNAMES found"
            r_dict['data'] = cname_list
        else:
            r_dict['status'] = RC.NOT_OK
            r_dict['msg'] = "CNAMES not found"
        # End of if/else
    # End of if

    return r_dict
    # End of find_cnames


# --------------------------------------------------------------------
#
# find_msk_cnames
#
# --------------------------------------------------------------------
def find_msk_cnames(arcade_name: str) -> dict:
    """
    """
    RS = common.ReturnStatus()

    msk_cname_list = []
    msk_cnames_found = False
    
    r_dict = _find_cnames(arcade_name)
    if r_dict['status'] == RS.FAIL:
        pass
    elif r_dict['status'] == RS.OK:
        cname_list = r_dict['data']
        for entry in cname_list:
            record_name = entry['Name']
            if 'kafka' in record_name or 'zookeeper' in record_name:
                msk_cnames_found = True
                msk_cname_list.append(entry)

        if msk_cnames_found:
            r_dict = common.gen_return_dict("In find_cnames")
            r_dict['data']   = msk_cname_list
            r_dict['msg']    = 'MSK CNAMES found'
            r_dict['status'] = RS.FOUND
        else:
            r_dict['msk']    = 'MSK CNAMES not found'
            r_dict['status'] = RS.NOT_FOUND
        #
    else:
        # What am I doing here
        pass

    return r_dict
    # End of find_msk_cnames

    
# --------------------------------------------------------------------
#
# find_msk_health_checks
#
# --------------------------------------------------------------------
def find_msk_health_checks(arcade_name: str) -> dict:
    """
    """
    RS = common.ReturnStatus()
    msk_health_check_list = []
    msk_health_check_found = False

    r_dict = common.gen_return_dict("In find_cnames")
    r_dict = find_health_checks(arcade_name)

    if r_dict['status'] == RS.OK:
        health_check_list = r_dict['data']
        for entry in health_check_list:
            fqd_name = entry['HealthCheckConfig']['FullyQualifiedDomainName']
            if fqd_name.startswith('kafka') or fqd_name.startswith('zookeeper'):
                msk_health_check_found = True
                msk_health_check_list.append(entry)

    if msk_health_check_found == True:
        r_dict['status'] = RS.FOUND
        r_dict['msg'] = 'MSK Health Checks found'
        r_dict['data'] = msk_health_check_list
    else:
        r_dict['status'] = RS.NOT_FOUND
        r_dict['msg'] = 'MSK Health Checks not found'

    return r_dict
    # End of find_msk_health_checks


# --------------------------------------------------------------------
#
# find_health_checks
#
# --------------------------------------------------------------------
def find_health_checks(arcade_name: str) -> dict:
    """
    """
    RS = common.ReturnStatus()

    health_check_list = []
    health_check_found = False

    r_dict = common.gen_return_dict("In find_health_checks")
    r53_client = boto3.client('route53')
    hostedZoneId = grv.tld_to_zone_id(arcade_name)

    # Health Checks
    trimed_arcade_name = arcade_name.replace('.arc', '')

    try:
        response = r53_client.list_health_checks()
        HealthChecks = response['HealthChecks']
        if len(HealthChecks) > 0:
            for entry in HealthChecks:
                caller_reference = entry['CallerReference']
                if trimed_arcade_name in caller_reference:
                    health_check_list.append(entry)
                    health_check_found = True
                # End of if
            # End of for loop
        # End of if
    except (Route53.Client.exceptions.InvalidInput,
            Route53.Client.exceptions.IncompatibleVersion) as err:
        r_dict = common.gen_return_dict("ERROR: caught an exception")
        r_dict['status'] = RS.FAIL
        r_dict['data'] = err

    if r_dict['status'] == RS.FAIL:
        pass

    if health_check_found == True:
        r_dict['status'] = RS.OK
        r_dict['msg'] = 'Health Checks found'
        r_dict['data'] = health_check_list
    else:
        r_dict['status'] = RS.NOT_FOUND
        r_dict['msg'] = 'Health Checks not found'

    return r_dict
    # End of find_health_checks


# --------------------------------------------------------------------
#
# delete_msk_dns_records
#
# --------------------------------------------------------------------
def delete_msk_dns_records(arcade_name: str ) -> dict:
    """
    Delete the MSJ CNAMEs and HealthChecks

    Args:
        arcade_name: the name of the arcade whose MSK DNS records
        are being deleted

    Returns:
        r_dict: A dict created by gen_return_dict
    """
    RS = common.ReturnStatus()

    r_dict = common.gen_return_dict('in delete_msk_dns_records')

    r53_client = boto3.client('route53')

    hostedZoneId = grv.tld_to_zone_id(arcade_name)

    try:
        response = r53_client.list_resource_record_sets(
            HostedZoneId=hostedZoneId)
    except (Route53.Client.exceptions.NoSuchHostedZone,
            Route53.Client.exceptions.InvalidInput) as err:
        r_dict = common.gen_return_dict('Error listing resource records')
        r_dict['data'] = err
        r_dict['status'] = RS.FAIL

    if r_dict['status'] == RS.OK:
        ResourceRecords = response['ResourceRecordSets']
        for entry in ResourceRecords:
            recordType = entry['Type']
            if recordType == 'CNAME':
                recordName = entry['Name']
                if 'kafka' in recordName or 'zookeeper' in recordName:
                    setIdentifier = entry['SetIdentifier']
                    ttl = entry['TTL']
                    weight = entry['Weight']
                    healthCheckId = entry['HealthCheckId']
                    value = entry['ResourceRecords'][0]['Value']

                    try:
                        response = r53_client.change_resource_record_sets(
                            HostedZoneId=hostedZoneId,
                            ChangeBatch={
                                'Changes': [
                                    {
                                        'Action': 'DELETE',
                                        'ResourceRecordSet': {
                                            'Name': recordName,
                                            'Type': 'CNAME',
                                            'SetIdentifier': setIdentifier,
                                            'Weight': weight,
                                            'TTL': ttl,
                                            'ResourceRecords': [
                                                { 'Value': value },
                                                ],
                                            'HealthCheckId': healthCheckId
                                            }
                                        },
                                    ]
                                }
                            )
                    except (Route53.Client.exceptions.NoSuchHostedZone,
                            Route53.Client.exceptions.NoSuchHealthCheck,
                            Route53.Client.exceptions.InvalidChangeBatch,
                            Route53.Client.exceptions.InvalidInput,
                            Route53.Client.exceptions.PriorRequestNotComplete) as err:
                        r_dict = common.gen_return_dict('Error deleting resource records')
                        r_dict['data'] = err
                        r_dict['status'] = RS.FAIL
                        break
                    # End of try block
                # End of if
            # End of if
        # End of for loop
    # End of if

    r_dict['msg'] = 'Success records deletes'

    return r_dict
    # End of delete_msk_dns_records


# --------------------------------------------------------------------
#
# delete_msk_health_checks
#
# --------------------------------------------------------------------
def delete_msk_health_checks(arcade_name):
    """
    Delete HealthChecks

    Args:
        Dict containing data

    Returns:
        A return code 0 == OK, 1 == Not OK
    """
    RS = common.ReturnStatus()
    r_dict = common.gen_return_dict(arcade_name)

    arcade_name = arcade_name.replace('.arc', '')
    r53_client = boto3.client('route53')

    try:
        response = r53_client.list_health_checks()
    except (Route53.Client.exceptions.InvalidInput,
            Route53.Client.exceptions.IncompatibleVersion) as err:
        r_dict['status'] = RS.FAIL
        r_dict['msg'] = 'Error list_health_checks failed'
        r_dict['msg'] = err
    # End of try block

    if r_dict['status'] == RS.OK:
        health_checks = response['HealthChecks']

        for entry in health_checks:
            caller_reference = entry['CallerReference']
            if arcade_name in caller_reference:
                health_check_id = entry['Id']
                fqd_name = entry['HealthCheckConfig']['FullyQualifiedDomainName']
                if 'kafka' in fqd_name or 'zookeeper' in fqd_name:
                    try:
                        response = r53_client.delete_health_check(
                            HealthCheckId = health_check_id)
                    except (Route53.Client.exceptions.NoSuchHealthCheck,
                            Route53.Client.exceptions.HealthCheckInUse,
                            Route53.Client.exceptions.InvalidInput) as err:
                        r_dict['status'] = RS.FAIL
                        r_dict['msg'] = 'Error delete_health_checks failed'
                        r_dict['msg'] = err
                else:
                    continue
                # End of if
            else:
                continue
            # End of if
        # End of for loop
    # If enr of if
    r_dict['msg'] = 'MSK health checks deleted'

    return r_dict
    # End of delete_msk_health_checks

    
# --------------------------------------------------------------------
#
# count_cnames
#
# --------------------------------------------------------------------
def count_cnames(arcade_name: str) -> dict:
    """
    Returns a count of all the CNAMES of an arcade

    Args:
        arcade_name: A string containg the name of an arcade

    Returns:
        r_dict: A return dict containing the count of the CNAMES
        stored in the dict key 'data'
    """

    RS = common.ReturnStatus
    r_dict = common.gen_return_dict('in count_cnames')

    cname_count = 0
    hosted_zone_id = grv.tld_to_zone_id(arcade_name)

    try:
        r53_client = boto3.client('route53')
        response = r53_client.list_resource_record_sets(
            HostedZoneId=hosted_zone_id)

        resource_record_sets = response['ResourceRecordSets']
        for entry in resource_record_sets:
            record_type = entry['Type']
            if record_type == 'CNAME':
                cname_count += 1

    except (Route53.Client.exceptions.NoSuchHostedZone,
            Route53.Client.exceptions.InvalidInput) as err:
        r_dict = common.gen_return_dict("ERROR: caught an exception")
        r_dict['status'] = RS.FAIL
        r_dict['data'] = err

    if r_dict['status'] == RS.OK:
        r_dict['msg'] = 'CNAME count'
        r_dict['data'] = cname_count

    return r_dict
    # End of count_cnames
