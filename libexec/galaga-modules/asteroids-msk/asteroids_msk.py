# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
asteroids-msk -- ARCADE MSK write functions
"""

# @depends: python (>=3.7)
__version__ = '0.1.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""

import json
import logging
import os
import random
import string
import time
import yaml

import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from arclib import alb
from arclib import common
from arclib import dns
from arclib import eks
from arclib import grv
from arclib import msk


# --------------------------------------------------------------------
#
# create_arcade_nlb
#
# --------------------------------------------------------------------
def create_arcade_nlb(arcade_name: str,
                      public: bool) -> dict:
    """
    Create an Network Load Balancer.

    Args:
        arcade_name: ARCADE name
        public: is this a public or internal nlb

    Returns:
        dict of nlb status response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')

    nlb_dict = alb.get_nlb_dict(arcade_name, public)

    subnets = grv.find_grv_subnets(arcade_name, nlb_dict['subnet_name'])

    if not subnets:
        return {'Code': 'failed',
                'Reason': f"{nlb_dict['subnet_name']} subnets do not exists for {arcade_name}"}

    response = elb_client.create_load_balancer(
        Name=nlb_dict['name'],
        Subnets=subnets,
        Scheme=nlb_dict['scheme'],
        Tags=[
            {
                'Key': 'Name',
                'Value': nlb_dict['name'],
            },
            {
                'Key': 'arcade_tool_provisioned',
                'Value': common.get_account_id(),
            },
            {
                'Key': 'grv_create_session_id',
                'Value': grv.validate_create_id(arcade_name),
            },
            {
                'Key': 'grv_name',
                'Value': arcade_name,
            }
        ],
        Type='network',
    )

    # nlb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    status = alb.get_alb_status(nlb_dict['name'])

    while 'provisioning' == status['State']['Code']:
        print(f"Waiting for the nlb {nlb_dict['name']} to be active")
        time.sleep(20)
        status = alb.get_alb_status(nlb_dict['name'])

    print(f"{nlb_dict['name']} NLB Created with scheme {nlb_dict['scheme']}")

    target = status['DNSName']
    source = f"{target.split('-')[0]}_nlb.{arcade_name}"
    dns.add_arcade_cname(arcade_name, source, target)

    return status


# --------------------------------------------------------------------
#
# delete_arcade_nlb
#
# --------------------------------------------------------------------
def delete_arcade_nlb(arcade_name: str,
                      public: bool) -> bool:
    """
    Delete an NLB.

    Args:
        arcade_name: ARCADE name to delete NLBs from
        public: is this a public or internal nlb

    Returns:
    True if nlb is deleted or not available, or False
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')

    nlb_dict = alb.get_nlb_dict(arcade_name, public)

    dns_name = f"{nlb_dict['name'].split('-')[0]}_nlb.{arcade_name}"
    dns.delete_arcade_cname(arcade_name, dns_name)

    nlb_arn = alb.find_alb_arn(nlb_dict['name'])

    if not nlb_arn:
        return True

    response = elb_client.delete_load_balancer(LoadBalancerArn=nlb_arn)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return False

    print(f"Deleted nlb {nlb_dict['name']}")

    return True


# --------------------------------------------------------------------
#
# create_policy
#
# --------------------------------------------------------------------
def create_policy(policy_name: str,
                  policy_document: str) -> str:
    """
    Create a AWS policy.

    Args:

    Returns:

    """
    json_object = json.dumps(policy_document)
    arcade_session = boto3.session.Session()
    iam_client = arcade_session.client('iam')
    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json_object,
            Tags=[
                {
                    'Key': 'arcade_tool_provisioned',
                    'Value': common.get_account_id()
                }
            ]
        )
    except ClientError as c_e:
        logging.debug(c_e)
        return c_e

    return response['Policy']['Arn']


# --------------------------------------------------------------------
#
# create_role
#
# --------------------------------------------------------------------
def create_role(role_name: str,
                policy_arns: list,
                assume_policy,
                custom_policy=None) -> str:
    """
    Create a role and attaches the initial policy to the role.

    Args:
        role_name: the role name
        policy_arns: the arns of policy
        assume_policy: policy string
        custom_policy: custom configuration for access that is not a provided policy

    Returns:
        the ARN of the Role
    """
    arcade_session = boto3.session.Session()
    iam_client = arcade_session.client('iam')

    json_object = json.dumps(assume_policy)

    if custom_policy:
        custom_policy_arn = create_policy("ECRAccessPolicy", custom_policy)
        policy_arns.append(custom_policy_arn)

    response = grv.find_role(role_name)

    if not response:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json_object,
            Tags=[
                {
                    'Key': 'arcade_tool_provisioned',
                    'Value': common.get_account_id()
                }
            ]
        )

    for arn in policy_arns:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=arn,
        )
    return response['Role']['Arn']


# --------------------------------------------------------------------
#
# create_msk
#
# --------------------------------------------------------------------
def create_msk(arcade_name: str,
               cluster_prefix: str,
               instance_type: str,
               brokers_per_az: int,
               ebs_size: int,
               kafka_version: str = '2.6.2') -> dict:
    """
    Create an EKS cluster.

    Args:
        cluster_prefix: the prefix of a cluster
        arcade_name: arcade_name name
        instance_type: kafka instance type kafka.m5.large
        brokers_per_az: brokers per az
        ebs_size: size of the ebs volume per broker
        kafka_version: kafka version. Defaults to '2.6.2'.

    Returns:
        status dict of the response or exception dict
    """
    msk_name = f"{cluster_prefix}-{arcade_name.replace('_', '').replace('.', '-')}"

    status = msk.get_msk_info(msk_name)
    print(status)

    if not status:
        # Create the cluster when it does not exist.
        msk_sg_name = f"{cluster_prefix}_msk.{arcade_name}"
        vpc_id = grv.get_vpc_id(arcade_name)

        msk_sg_id = grv.check_if_sg(msk_sg_name)
        if not msk_sg_id:
            msk_sg_id = grv.create_grv_sg(sg_name=msk_sg_name, vpc_id=vpc_id)

        msk_client = boto3.client('kafka')

        core_subnets = grv.find_grv_subnets(arcade_name, "core")
        number_of_brokers = len(core_subnets) * brokers_per_az
        msk_config = msk.get_msk_configuration(msk_name)
        if not msk_config:
            return msk_config
        msk_config_arn = msk_config['Arn']
        msk_config_rev = msk_config['LatestRevision']['Revision']
        print(f'Creating MSK cluster {msk_name}...')
        status = msk_client.create_cluster(
            BrokerNodeGroupInfo={
                'BrokerAZDistribution': 'DEFAULT',
                'ClientSubnets': core_subnets,
                'InstanceType': instance_type,
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
                'grv_name': arcade_name,
                'creator': grv.aws_whoami(),
                'arcade_tool_provisioned': common.get_account_id(),
                'grv_create_session_id': grv.validate_create_id(arcade_name),
            }
        )

        while 'CREATING' == status.get('State'):
            print(f'Waiting for the MSK cluster {msk_name} to be active.')
            time.sleep(120)
            status = msk.get_msk_info(msk_name)

        print(f"Cluster {msk_name} is created!")
    elif 'CREATING' == status.get('State'):
        while 'CREATING' == status.get('State'):
            print(f'Waiting for the MSK cluster {msk_name} to be active.')
            time.sleep(120)
            status = msk.get_msk_info(msk_name)
    else:
        print(f'MSK cluster {msk_name} already exists, status: {status["State"]}')

    return status
    #


# --------------------------------------------------------------------
#
# create_msk_configuration
#
# --------------------------------------------------------------------
def create_msk_configuration(arcade_name: str,
                             cluster_prefix: str,
                             kafka_version: str,
                             server_properties: str) -> dict:
    """
    Create an MSK configuration for the MSK cluster, if it doesn't already exist.

    Args:
        arcade_name: arcade_name name
        cluster_prefix: the prefix of a cluster
        kafka_version: version of kafka for this configuration
        server_properties: kafka options

    Returns:
        status dict of the response or get
    """
    msk_name = f"{cluster_prefix}-{arcade_name.replace('_', '').replace('.', '-')}"

    status = msk.get_msk_configuration(msk_name)

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
    #


# --------------------------------------------------------------------
#
# delete_msk
#
# --------------------------------------------------------------------
def delete_msk(arcade_name: str,
                cluster_prefix: str) -> dict:
    """
    Delete MSK cluster with given cluster prefix.

    Args:
        arcade_name: name of arcade_name
        cluster_prefix: name of the msk to be deleted

    Returns:
        empty dict if deletion happens otherwise status is returned
    """
    msk_name = f"{cluster_prefix}-{arcade_name.replace('_', '').replace('.', '-')}"
    msk_sg_name = f"{cluster_prefix}_msk.{arcade_name}"

    status = msk.get_msk_info(msk_name)

    if not status:
        grv.delete_grv_sg(msk_sg_name)
        return status

    if status and 'DELETING' == status['State']:
        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk cluster {msk_name} to be deleted.')
            time.sleep(30)
            status = msk.get_msk_info(msk_name)
    else:
        msk_client = boto3.client('kafka')
        print(f'Deleting msk cluster {msk_name}...')
        msk_arn = status['ClusterArn']
        status = msk_client.delete_cluster(ClusterArn=msk_arn)

        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk cluster {msk_name} to be deleted.')
            time.sleep(30)
            status = msk.get_msk_info(msk_name)

    grv.delete_grv_sg(msk_sg_name)
    return status
    #


# --------------------------------------------------------------------
#
# delete_msk_configuration
#
# --------------------------------------------------------------------
def delete_msk_configuration(arcade_name: str,
                              cluster_prefix: str) -> dict:
    """
    Delete msk configuration

    Args:
        arcade_name: the name of arcade_name
        cluster_prefix: the prefix of cluster

    Returns:
        empty dict if deletion happens otherwise status is returned
    """
    msk_name = f"{cluster_prefix}-{arcade_name.replace('_', '').replace('.', '-')}"

    status = msk.get_msk_configuration(msk_name)

    if not status:
        return status

    if status and 'DELETING' == status['State']:
        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk configuration {msk_name} to be deleted.')
            time.sleep(30)
            status = msk.get_msk_configuration(msk_name)
            logging.debug(status)
    else:
        msk_client = boto3.client('kafka')
        msk_config_arn = status['Arn']
        status = msk_client.delete_configuration(Arn=msk_config_arn)

        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk configuration {msk_name} to be deleted.')
            time.sleep(30)
            status = msk.get_msk_configuration(msk_name)
            logging.debug(status)

    logging.debug(status)

    return status


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

    kafka_client = boto3.client('kafka')

    status_dict = msk.get_msk_status(cluster_name)
    if status_dict['State'] == 'ACTIVE':
        try:
            Response = kafka_client.list_clusters()
            ClusterInfo = Response['ClusterInfoList']
        except ClientError as err:
            # BadRequestException
            # InternalServerErrorException
            # UnauthorizedException
            # ForbiddenException
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
                        Response = kafka_client.describe_cluster(ClusterArn=clusterArn)
                        ci = Response['ClusterInfo']
                        zookeeperConnectString    = ci['ZookeeperConnectString']
                        connStrings = zookeeperConnectString.split(',')
                    except ClientError as err:
                        # NotFoundException
                        # BadRequestException
                        # UnauthorizedException
                        # InternalServerErrorException
                        # ForbiddenException
                        r_dict['status'] = RS.FAIL
                        r_dict['msg'] = 'Error describe_cluster failed'
                        r_dict['data'] = err
                        break
                    # End of try block
                else:
                    # kafka
                    try:
                        Response = kafka_client.get_bootstrap_brokers(ClusterArn=clusterArn)
                        bootstrapBrokerString = Response['BootstrapBrokerStringTls']
                        connStrings = bootstrapBrokerString.split(',')
                    except ClientError as err:
                        # BadRequestException
                        # UnauthorizedException
                        # InternalServerErrorException
                        # ConflictException
                        # ForbiddenException
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

    except ClientError as err:
        # NoSuchHostedZone
        # InvalidInput
        r_dict = common.gen_return_dict("ERROR: caught an exception")
        r_dict['status'] = RS.FAIL
        r_dict['data'] = err

    if r_dict['status'] == RS.OK:
        r_dict['msg'] = 'CNAME count'
        r_dict['data'] = cname_count

    return r_dict
    # End of count_cnames


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
    RS = common.ReturnStatus()
    connStrings = p_dict['connStrings']
    arcadeName  = p_dict['arcadeName']
    serviceName = p_dict['serviceName']
    entry_index = p_dict['entry_index']

    domainName = arcadeName.replace('_', '-')

    r53_client = boto3.client('route53')
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
            response = r53_client.change_resource_record_sets(
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
        except ClientError as err:
            # NoSuchHostedZone
            # NoSuchHealthCheck
            # InvalidChangeBatch
            # InvalidInput
            # PriorRequestNotComplete
            r_dict = common.gen_return_dict("ERROR: caught an exception")
            r_dict['status'] = RS.FAIL
            r_dict['data'] = err

    # End of for loop

    r_dict['entry_index'] = entry_index

    return r_dict
    # End of _add_dns_record


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
    except ClientError as err:
        # InvalidInput
        # IncompatibleVersion
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
            except ClientError as err:
                # TooManyHealthChecks
                # HealthCheckAlreadyExists
                # InvalidInput
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
                                    {
                                        'Key': 'grv_create_session_id',
                                        'Value': grv.validate_create_id(arcadeName),
                                    },
                                ]
                        )
                except ClientError as err:
                    # InvalidInput
                    # NoSuchHealthCheck
                    # NoSuchHostedZone
                    # PriorRequestNotComplete
                    # ThrottlingException
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
# _id_generator
#
# --------------------------------------------------------------------
def _id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
    # End of _id_generator


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
    except ClientError as err:
        # NoSuchHostedZone
        # InvalidInput
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
                    except ClientError as err:
                        # NoSuchHostedZone
                        # NoSuchHealthCheck
                        # InvalidChangeBatch
                        # InvalidInput
                        # PriorRequestNotComplete
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
    except ClientError as err:
        # InvalidInput
        # IncompatibleVersion
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
                    except ClientError as err:
                        # NoSuchHealthCheck
                        # HealthCheckInUse
                        # InvalidInput
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
