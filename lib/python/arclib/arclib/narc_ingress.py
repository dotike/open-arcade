# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
narc_ingress --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.5'

import asyncio
import logging
import boto3
from kubernetes import client, config
from botocore.exceptions import ClientError

from arclib import common, grv, alb


# --------------------------------------------------------------------
#
# find_alb_arn
#
# --------------------------------------------------------------------
def find_alb_arn(alb_name: str) -> str:
    """
    Find the ALB Arn.

    Args:
        alb_name (str): [Name TAG of the ALB]

    Returns:
        [str]: [ARN of the given ALB]
    """
    elb_client = boto3.client('elbv2')

    try:
        alb_arns = elb_client.describe_load_balancers(Names=[alb_name])
        logging.info(alb_arns['LoadBalancers'][0]['LoadBalancerArn'])
        return alb_arns['LoadBalancers'][0]['LoadBalancerArn']
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        return c_e

    # End of find_alb_arn


# --------------------------------------------------------------------
#
# find_available_rule_priority
#
# --------------------------------------------------------------------
def find_available_rule_priority(arcade_name: str, listner_arn: str):
    """
    Find the rule prioirity.

    Args:
        arcade_name (str): Name of the arcade
        listner_arn (str): Listener ARN

    Returns:
        [str]: [prioirty]
    """
    elb_client = boto3.client('elbv2')

    try:
        response = elb_client.describe_rules(
            ListenerArn=listner_arn,
        )
    except ClientError as c_e:
        logging.info(c_e)
        r_dict = common.handle_boto_error(c_e)
        return c_e

    priority = 0
    for rule in response['Rules']:
        logging.info(rule)
        if rule['Priority'] == 'default':
            continue
        if int(rule['Priority']) > priority:
            priority = int(rule['Priority'])
            logging.info(priority)

    return str(priority + 1)
    # End of find_available_rule_priority


# --------------------------------------------------------------------
#
# find_listner_arn
#
# --------------------------------------------------------------------
def find_listner_arn(arcade_name: str, prefix) -> tuple:
    """
    Find the Listener ARN of a ALB.

    Args:
        asd_data (dict): [ASD data]
        arcade_name (str): [Arcade Name]

    Returns:
        tuple: [ALB Listener ARN and ALB ARN]
    """
    elb_client = boto3.client('elbv2')

    alb_name = f"{prefix}-{arcade_name.replace('_', '').replace('.', '-')}"

    try:
        response = elb_client.describe_listeners(
            LoadBalancerArn=find_alb_arn(alb_name=alb_name),
        )
        return response['Listeners'][0]['ListenerArn'], response['Listeners'][0]['LoadBalancerArn']
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        return c_e
    # End of find_listner_arn


# --------------------------------------------------------------------
#
# create_alb_rule
#
# --------------------------------------------------------------------
def create_alb_rule(arcade_name: str, listener_arn: str, narc_id: str, target_grp_arn: str, tags={}):
    """
    Create an ALB rule to forward to the Target Group.

    Args:
        arcade_name (str): [Arcade Name]
        listener_arn (str): [ALB Listener ARN]
        narc_id (str): [Id of The NARC ID]
        target_grp_arn (str): [Target Group ARN]
        tags (dict): [Custom tags defined in ASD]

    Returns:
        [dict]: [response]
    """
    # Assemble tags list
    tag_list = [{
        'Key': 'Name',
        'Value': narc_id,
    }]

    for key, val in tags.items():
        tag_list.append({
            'Key': key,
            'Value': val
        })

    response = {}
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.create_rule(
            Priority=int(find_available_rule_priority(arcade_name='', listner_arn=listener_arn)),
            ListenerArn=listener_arn,
            Conditions=[
                {
                    'Field': 'path-pattern',
                    'Values': [
                        f'/{narc_id}*'
                    ]
                }
            ],
            Actions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': target_grp_arn
                }
            ],
            Tags=tag_list
        )

    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        # response = r_dict

    return response
    # End of create_alb_rule


# --------------------------------------------------------------------
#
# create_alb_listener
#
# --------------------------------------------------------------------
def create_alb_listener(arcade_name: str, narc_id: str, target_grp_arn: str, prefix: str, tags={}):
    """
    Create ALB listener.

    Args:
        arcade_name (str): [Arcade Name]
        narc_id (str): [Id of The NARC ID]
        target_grp_arn (str): [Target Group ARN]
        prefix (str): public or private
        tags (dict): [Custom tags defined in ASD]

    Returns:
        [dict]: [response]
    """
    response = {}

    # Assemble tags list
    tag_list = [{
        'Key': 'Name',
        'Value': narc_id,
    }]

    for key, val in tags.items():
        tag_list.append({
            'Key': key,
            'Value': val
        })

    elb_client = boto3.client('elbv2')
    asteroid_name = narc_id.replace('-', ' ').split()[1]
    asteroid_port = get_asteroid_port(narc_id=narc_id, asteroid=asteroid_name)
    alb_name = f"{prefix}-{arcade_name.replace('_', '').replace('.', '-')}"
    alb_arn = find_alb_arn(alb_name=alb_name)

    try:
        response = elb_client.create_listener(
            LoadBalancerArn=alb_arn,
            Port=asteroid_port,
            Protocol='HTTP',
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': target_grp_arn,
                },
            ],
            Tags=tag_list
        )
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])

    return response
    # End of create_alb_listner


# --------------------------------------------------------------------
#
# authorize_alb_listener
#
# --------------------------------------------------------------------
def authorize_alb_listener(arcade_name: str, narc_id: str, prefix: str):
    """
    Athorize ALB listener.

    Args:
        arcade_name (str): [Arcade Name]
        narc_id (str): [Id of The NARC ID]
        prefix (str): public or private

    Returns:
        [dict]: [response]
    """
    ec2_client = boto3.client('ec2')
    asteroid_name = narc_id.replace('-', ' ').split()[1]
    asteroid_port = get_asteroid_port(narc_id=narc_id, asteroid=asteroid_name)
    sg_name = f"{prefix}_alb.{arcade_name}"
    logging.info(sg_name)
    sg_id = grv.check_if_sg(sg_name=sg_name)
    logging.info(sg_id)
    logging.info(asteroid_port)

    response = {}
    try:
        response = ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': asteroid_port,
                    'ToPort': asteroid_port,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': f'{narc_id}'}]
                }
            ],
            TagSpecifications=[
                {
                    'ResourceType': 'security-group-rule',
                    'Tags': [
                        {
                            'Key': 'narc_id',
                            'Value': narc_id
                        },
                    ]
                },
            ]
        )

    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        # response = r_dict
        # logging.debug(response)

    return response
    # End of authorize_alb_listener


# --------------------------------------------------------------------
#
# revoke_alb_listener
#
# --------------------------------------------------------------------
def revoke_alb_listener(arcade_name: str, narc_id: str, asteroid_port: int, prefix: str):
    """
    Athorize ALB listener.

    Args:
        arcade_name (str): [Arcade Name]
        narc_id (str): [Id of The NARC ID]
        asteroid_port (int): [port used by the target_group/sg rule]
        prefix (str): public or private

    Returns:
        [dict]: [response]
    """
    response = {}
    ec2_client = boto3.client('ec2')
    sg_name = f"{prefix}_alb.{arcade_name}"
    logging.info(sg_name)
    sg_id = grv.check_if_sg(sg_name=sg_name)
    logging.info(sg_id)
    logging.info(narc_id)
    logging.info(asteroid_port)

    try:
        response = ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            CidrIp='0.0.0.0/0',
            IpProtocol='tcp',
            FromPort=asteroid_port,
            ToPort=asteroid_port
        )
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        # logging.debug(c_e)

    logging.debug(response)

    return response
    # End of revoke_alb_listener


# --------------------------------------------------------------------
#
# get_asteroid_port
#
# --------------------------------------------------------------------
def get_asteroid_port(narc_id: str, asteroid: str):
    """
    Args:
        narc_id
        asteroid
        
    Returns:
        node_port
    """
    node_port = ''
    core_v1 = client.CoreV1Api()

    # Create short service name by truncating narc_id to everything after the second "-"
    short_service_name = narc_id[narc_id.find('-', narc_id.find('-') + 1) + 1:]

    try:
        asteroid_port = core_v1.read_namespaced_service(name=short_service_name,
                                                        namespace=asteroid)
        node_port = asteroid_port.spec.ports[0].node_port
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])

    return node_port
    # End of get_asteroid_port


# --------------------------------------------------------------------
#
# valiadate_grv_id
#
# --------------------------------------------------------------------
def validate_grv_id(grv_id: str):
    """
    Args:
        grv_id
        
    Returns:
        response
    """
    try:
        ec2_client = boto3.client('ec2')
        if not grv_id == '':
            try:
                # straight for the answer,
                response = ec2_client.describe_vpcs(
                    DryRun=False,
                    VpcIds=[grv_id]
                )['Vpcs'][0]['VpcId']

            except Exception as err1:
                # filter query to keep it light payload,
                try:
                    vlist = ec2_client.describe_vpcs(
                        DryRun=False,
                        Filters=[{'Name': 'tag:Name', 'Values': [grv_id]}, ],
                    )['Vpcs']
                    # now uplack that result and straight for the answer again,
                    if len(vlist) == 1:
                        # this is the common case
                        response = vlist[0]['VpcId']
                    # if that didn't work, do we have any results?
                    elif not vlist:
                        msg = f"No 'grv_id' in AWS with tag:Name or Object ID '{grv_id}'"
                        raise ValueError(msg)
                    # finally, we must have too many results, (rare and broken case),
                    else:
                        response = []
                        for avpc in vlist:
                            response.append(avpc['VpcId'])

                except Exception as err2:
                    emsg = f"AWS or boto error: {err1}: {err2}"
                    raise EnvironmentError(emsg)
        else:
            vmsg = f"validate_grv_id() given '{grv_id}', does not handle empty string grv names."
            raise ValueError(vmsg)

        return response

    except Exception as err:
        raise type(err)(f'validate_grv_id(): {err}')
    # End of validate_grv_id


# --------------------------------------------------------------------
#
# eks_asg_name
#
# --------------------------------------------------------------------
def eks_asg_name(eks_cluster: str) -> str:
    """
    Return an asg from a eks cluster.

    Args:
        eks_cluster (str): Name of the EKS cluster

    Returns:
        [str]: arn of eks asg
    """
    eks_client = boto3.client('eks')
    try:
        ln_r = eks_client.list_nodegroups(clusterName=eks_cluster)
        response = eks_client.describe_nodegroup(clusterName=eks_cluster,
                                                 nodegroupName=ln_r['nodegroups'][0])

        return response['nodegroup']['resources']['autoScalingGroups'][0]['name']
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        return c_e
    # End of eks_asg_name


# --------------------------------------------------------------------
#
# register_targets
#
# --------------------------------------------------------------------
def register_targets(target_grp_arn: str, targets: list) -> bool:
    """
    Register instances to a Target Group.

    Args:
        target_grp_arn (str): arn of the target group
        targets (list): list of dict of instance IDs
    """
    return_flag = True
    elb_client = boto3.client('elbv2')

    try:
        response = elb_client.register_targets(
            TargetGroupArn=target_grp_arn,
            Targets=targets)
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        return_flag = False

    return return_flag
    # End of register_targets


# --------------------------------------------------------------------
#
# get_instance_id
#
# --------------------------------------------------------------------
def get_instance_id(asg_name: str, instance_port: int) -> list:
    """
    Get a list of instances and returns them for the Target Group attachment.

    Args:
        asg_name (str): AutoScalingGroup Name
        instance_port (int): Instance Port
    Returns:
        [list]: list of dict
    """
    as_client = boto3.client('autoscaling')
    instance_info = []
    return_value = []

    try:
        asg_data = as_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name])

        for line in asg_data['AutoScalingGroups']:
            for instance in line['Instances']:
                data = {
                    'Id': instance['InstanceId'],
                    'Port': instance_port,
                }
                instance_info.append(data)
        return_value = instance_info
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        # return_value =  c_e

    return return_value
    # End of get_instance_id


# --------------------------------------------------------------------
#
# create_asteroid_taget_group
#
# --------------------------------------------------------------------
def create_asteroid_target_group(arcade_name: str, prefix: str, asd_data: dict, tags={}) -> str:
    """
    Create a target group for a public or private ALB to a target group.

    Creates a target group.

    Args:
        arcade_name (str): Arcade Name ex: icy_lake.grv
        prefix (str): public or private target group
        asd_data ([dict]): ASD/NARC data
        tags (dict): [Custom tags defined in ASD]

    Returns:
        [str]: Target group ARN
    """
    return_str = ''
    elb_client = boto3.client('elbv2')

    narc_id = asd_data['service']
    lb_type = prefix[:3]
    # tg_name = f"{common.get_short_narc_id(narc_id.replace('narc', lb_type))}-{arcade_name.replace('_', '').replace('.', '')}"
    tg_name = alb.create_unique_targetgroup_name(arcade_name, narc_id, prefix)
    uri_endpoint = asd_data['containers'][0]['readiness_check_path']
    port = asd_data['containers'][0]['port_mappings'][0]['port']
    # vpc_id = validate_grv_id(grv_id=arcade_name)
    vpc_id = grv.get_vpc_id(grv_name=arcade_name)

    asteroid_name = narc_id.replace('-', ' ').split()[1]
    # Use the nodeport for both traffic routing and healthchecks
    asteroid_port = get_asteroid_port(narc_id=narc_id, asteroid=asteroid_name)

    if port == 443:
        protocol = 'HTTPS'
    else:
        protocol = 'HTTP'

    # Assemble tags list
    tag_list = [{
        'Key': 'Name',
        'Value': narc_id,
    }]

    for key, val in tags.items():
        tag_list.append({
            'Key': key,
            'Value': val
        })

    # Use sane defaults if no data provided
    readiness_check_path = '/'
    readiness_check_scheme = 'HTTP'

    if "readiness_check_path" in asd_data['containers'][0]:
        readiness_check_path = asd_data['containers'][0]['readiness_check_path']

    if "readiness_check_https" in asd_data['containers'][0]:
        if asd_data['containers'][0]['readiness_check_https']:
            readiness_check_scheme = 'HTTPS'
    try:
        response = elb_client.create_target_group(
            Name=f'{tg_name}',
            Protocol=protocol,
            ProtocolVersion='HTTP1',
            Port=asteroid_port,
            VpcId=vpc_id,
            HealthCheckProtocol=readiness_check_scheme,
            HealthCheckPort=str(asteroid_port),
            HealthCheckEnabled=True,
            HealthCheckPath=readiness_check_path,
            HealthCheckIntervalSeconds=5,
            HealthCheckTimeoutSeconds=2,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={
                'HttpCode': '200',
            },
            TargetType='instance',
            Tags=tag_list)
        return_str = response['TargetGroups'][0]['TargetGroupArn']

    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])

    return return_str
    # End of create_asteroid_target_group


# --------------------------------------------------------------------
#
# create_asteroid_ingress
#
# --------------------------------------------------------------------
def create_asteroid_ingress(arcade_name: str, asd_data, specific_prefix=None):
    """
    Create a Ingress Connection from a public or private ALB to a target group.

    Creates a Listener Rule and adds instnaces to the target group.

    Args:
        arcade_name (str): Arcade Name ex: icy_lake.grv
        asd_data ([dict]): ASD/NARC data
        specific_prefix (str): Public/Private for creating/deleting only specifically public or private LBs

    Returns:
        [type]: [description]
    """
    return_flag = False
    as_client = boto3.client('autoscaling')

    narc_id = asd_data['service']
    load_balanced = asd_data['service_options']['load_balanced']
    vpc_id = grv.get_vpc_id(grv_name=arcade_name)
    asteroid_name = narc_id.replace('-', ' ').split()[1]
    asteroid_port = get_asteroid_port(narc_id=narc_id, asteroid=asteroid_name)

    eks_cluster_name = f'asteroids-{arcade_name.replace(".", "-")}'

    try:
        eks_asg = eks_asg_name(eks_cluster=eks_cluster_name)
        # target_grp_targets = get_instance_id(asg_name=eks_asg, instance_port=asteroid_port)

        tags = {}
        if "tags" in asd_data:
            tags = asd_data["tags"]

        if specific_prefix:
            _create_lb(load_balanced, specific_prefix, arcade_name, asd_data, tags, as_client, eks_asg, narc_id)
        else:
            _create_lb(load_balanced, "private", arcade_name, asd_data, tags, as_client, eks_asg, narc_id)
            _create_lb(load_balanced, "public", arcade_name, asd_data, tags, as_client, eks_asg, narc_id)

        return_flag = True
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        # logging.info(c_e)
        return_flag = False

    return return_flag
    # End of create_asteroid_ingress


# --------------------------------------------------------------------
#
# create_asteroid_ingress_parallel
#
# --------------------------------------------------------------------
async def create_asteroid_ingress_parallel(arcade_name: str, asd_data, specific_prefix=None):
    """
    Create a Ingress Connection from a public or private ALB to a target group.

    Creates a Listener Rule and adds instnaces to the target group.

    Args:
        arcade_name (str): Arcade Name ex: icy_lake.grv
        asd_data ([dict]): ASD/NARC data
        specific_prefix (str): Public/Private for creating/deleting only specifically public or private LBs

    Returns:
        [type]: [description]
    """
    as_client = boto3.client('autoscaling')

    narc_id = asd_data['service']
    load_balanced = asd_data['service_options']['load_balanced']
    vpc_id = grv.get_vpc_id(grv_name=arcade_name)
    asteroid_name = narc_id.replace('-', ' ').split()[1]
    asteroid_port = get_asteroid_port(narc_id=narc_id, asteroid=asteroid_name)
    return_flag = False

    eks_cluster_name = f'asteroids-{arcade_name.replace(".", "-")}'

    try:
        eks_asg = eks_asg_name(eks_cluster=eks_cluster_name)
        # target_grp_targets = get_instance_id(asg_name=eks_asg, instance_port=asteroid_port)

        tags = {}
        if "tags" in asd_data:
            tags = asd_data["tags"]

        if specific_prefix:
            _create_lb(load_balanced, specific_prefix, arcade_name, asd_data, tags, as_client, eks_asg, narc_id)
        else:
            _create_lb(load_balanced, "private", arcade_name, asd_data, tags, as_client, eks_asg, narc_id)
            _create_lb(load_balanced, "public", arcade_name, asd_data, tags, as_client, eks_asg, narc_id)

        return_flag = True

    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        # logging.error(r_dict['msg'])
        logging.info(r_dict['msg'])
        return_flag = False

    return return_flag
    # End of create_asteroid_ingress_parallel


# --------------------------------------------------------------------
#
# find_tg
#
# --------------------------------------------------------------------
def find_tg(alb_arn: str) -> str:
    """
    Find the Target Group Attached to the ALB.

    Args:
        alb_arn (str): [ARN of the ALB]

    Returns:
        str: [Target Group ARN]
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_target_groups(LoadBalancerArn=alb_arn)
        return response['TargetGroups'][0]['TargetGroupArn']
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        # logging.info(r_dict['msg'])

        return c_e
    # End of find_tg


# --------------------------------------------------------------------
#
# get_asteroid_tg_info
#
# --------------------------------------------------------------------
def get_asteroid_tg_info(tg_name: str, narc_id) -> tuple:
    """
    JCG-NOTE: Leave this one alone.
    
    Get Target Group information based on the NARC ID.

    Args:
        tg_name (str): ARCADE target group name (alb.create_unique_targetgroup_name format)
        narc_id (str): [The Narc ID] (old necessary for support of old tg names)

    Returns:
        tuple: [TargetGroup ARN and ALB ARN and TargetGroup port]
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_target_groups(Names=[tg_name])
    except ClientError as c_e:
        if c_e.response['Error']['Code'] == 'ValidationError':
            return '', '', ''
        if c_e.response['Error']['Code'] == 'TargetGroupNotFound':
            return '', '', ''
        logging.info(c_e)
        raise c_e

    return response['TargetGroups'][0]['TargetGroupArn'], response['TargetGroups'][0]['LoadBalancerArns'], \
           response['TargetGroups'][0]['Port']
    # End of get_asteroid_tg_info


# --------------------------------------------------------------------
#
# get_listener_arn
#
# --------------------------------------------------------------------
def get_listener_arn(alb_arn, port=80) -> str:
    """
    Get the Listener ARN thats attached to the ALB.

    Args:
        alb_arn ([str]): [The arn of the ALB]
        port (int, optional): [description]. Defaults to 80.

    Returns:
        [str]: [listener arn]
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_listeners(LoadBalancerArn=alb_arn)
    except ClientError as c_e:
        logging.info(c_e)
        return c_e

    for listener in response['Listeners']:
        if listener['Port'] == port:
            return listener['ListenerArn']
    # End of get_listener_arn


# --------------------------------------------------------------------
#
# find_narc_rule
#
# --------------------------------------------------------------------
def find_narc_rule(listener_arn, narcid):
    """
    Args:
    Returns:
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_rules(ListenerArn=listener_arn)
    except ClientError as c_e:
        logging.info(c_e)
        return c_e

    logging.debug(response)
    for rule in response['Rules']:
        for condition in rule['Conditions']:
            for value in condition["Values"]:
                if narcid in value:
                    return rule['RuleArn']
    return ''
    # End of find_narc_rule


# --------------------------------------------------------------------
#
# delete_ingress
#
# --------------------------------------------------------------------
def delete_ingress(arcade_name: str, narc_id: str, specific_ingress=None) -> bool:
    """
    Delete Target group, the ALB Listener Rule and ALB SG Rule.

    Args:
        arcade_name (str): Arcade Name ex: icy_lake.grv
        narc_id (str): [NARC ID]

    Returns:
        [bool]
    """
    return_flag = False

    elb_client = boto3.client('elbv2')
    as_client = boto3.client('autoscaling')
    eks_cluster_name = f'asteroids-{arcade_name.replace(".", "-")}'
    eks_asg = eks_asg_name(eks_cluster=eks_cluster_name)

    try:
        if specific_ingress:
            _delete_lb(specific_ingress, arcade_name, narc_id, as_client, elb_client, eks_asg)
        else:
            _delete_lb("private", arcade_name, narc_id, as_client, elb_client, eks_asg)
            _delete_lb("public", arcade_name, narc_id, as_client, elb_client, eks_asg)
    except ClientError as c_e:
        r_dict = common.handle_boto_error(c_e)
        logging.error(r_dict['msg'])
        return_flag = False

    return return_flag
    # End of delete_ingress


# --------------------------------------------------------------------
#
# get_ingress_info
#
# --------------------------------------------------------------------
def get_ingress_info(arcade_name: str, asd_data: dict) -> dict:
    """
    JCG-NOTE: Not sure about this one
    
    Show Target group and the ALB Listener Rule.

    Args:
        asd_data: a dictionary of asd data

    Returns:
        [dict]
    """
    elb_client = boto3.client('elbv2')
    narcid = asd_data['service']
    asteroid_name = narcid.replace('-', ' ').split()[1]
    lb_data = {}
    for load_balancer in ['public', 'private']:
        lb_data[load_balancer] = {}
        logging.info(load_balancer)
        fixed_narc_id_tg = narcid.replace('narc', load_balancer[:3])
        logging.info(fixed_narc_id_tg)
        target_group_name = alb.create_unique_targetgroup_name(arcade_name, narcid, load_balancer)
        target_group_info = get_asteroid_tg_info(target_group_name, narcid)
        logging.info(target_group_info)
        if target_group_info[0]:
            # lb_data[load_balancer]['narc_id'] = narcid
            # lb_data[load_balancer]['asteroid_name'] = asteroid_name
            lb_data[load_balancer]['target_group'] = target_group_name
            target_group_arn = target_group_info[0]
            target_group_port = target_group_info[2]

            if not target_group_info[1]:
                logging.warning(f"{load_balancer} load balancer for {target_group_name} does not exist.")
                continue

            loadbalancer_arn = target_group_info[1][0]

            loadbalancer_info = \
            elb_client.describe_load_balancers(LoadBalancerArns=[loadbalancer_arn])['LoadBalancers'][0]
            lb_data[load_balancer]['dns'] = loadbalancer_info['DNSName']
            lb_data[load_balancer]['creation_timestamp'] = loadbalancer_info['CreatedTime']
            lb_data[load_balancer]['port'] = target_group_port
            _listener_arn = get_listener_arn(alb_arn=loadbalancer_arn, port=80)
            logging.info(_listener_arn)
            lb_rule_arn = find_narc_rule(_listener_arn, narcid)
            logging.info(lb_rule_arn)
            if lb_rule_arn:
                rule = elb_client.describe_rules(RuleArns=[lb_rule_arn])['Rules'][0]
                lb_data[load_balancer]['path'] = f'/{narcid}*'
                lb_data[load_balancer]['type'] = 'rule'
                # lb_data[load_balancer]['rule'] = rule
                logging.debug(rule)

            # NLB like behavior only needed until rules engine is available for ALB
            nlb_listener_arn = get_listener_arn(alb_arn=loadbalancer_arn, port=target_group_port)
            logging.info(nlb_listener_arn)
            if nlb_listener_arn:
                listener = elb_client.describe_listeners(ListenerArns=[nlb_listener_arn])['Listeners'][0]
                lb_data[load_balancer]['path'] = '/'
                lb_data[load_balancer]['type'] = 'port'
                # lb_data[load_balancer]['listener'] = listener
                logging.debug(listener)

            # delete_target_group = client.delete_target_group(TargetGroupArn=target_group_arn)
            # logging.debug(delete_target_group)

    return lb_data
    # End of get_ingress_info


# --------------------------------------------------------------------
#
# check_loadbalancers_for_modification
#
# --------------------------------------------------------------------
def check_loadbalancers_for_modification(arcade_name, asddata):
    """
    Compare load balancers defined within ASD against AWS and find changes.
    Will look to see if the state of public/private LB booleans in the ASD has changed.
    If any changed to True then LBs will be provisioned.  If any changed to false then LBs will be removed.
    """
    narc_id = asddata['service']
    public_alb_bool = asddata['service_options']['load_balanced']['public']
    private_alb_bool = asddata['service_options']['load_balanced']['private']

    elb_client = boto3.client('elbv2')
    as_client = boto3.client('autoscaling')
    eks_cluster_name = f'asteroids-{arcade_name.replace(".", "-")}'
    eks_asg = eks_asg_name(eks_cluster=eks_cluster_name)

    for load_balancer in ['public', 'private']:
        target_group_name = alb.create_unique_targetgroup_name(arcade_name, narc_id, load_balancer)
        target_group_info = get_asteroid_tg_info(target_group_name, narc_id)
        lb_exists = True
        if target_group_info[0]:
            target_group_arn = target_group_info[0]
            target_group_port = target_group_info[2]

            if not target_group_info[1]:
                logging.warning(f"{load_balancer} load balancer for {target_group_name} does not exist.")
                lb_exists = False

            loadbalancer_arn = target_group_info[1][0]

            # NLB like behavior only needed until rules engine is available for ALB
            nlb_listener_arn = get_listener_arn(alb_arn=loadbalancer_arn, port=target_group_port)
            if not nlb_listener_arn:
                logging.warning(f"NLB Listener ARN not found load balancer for {target_group_name} does not exist.")
                lb_exists = False
        else:
            lb_exists = False

        if load_balancer == "public":
            if public_alb_bool:
                # LB should exist
                if not lb_exists:
                    print(f"A PUBLIC load balancer has been turned on! creating...")
                    create_asteroid_ingress(arcade_name, asddata, "public")
            else:
                # LB should NOT exist
                if lb_exists:
                    print(f"A PUBLIC load balancer has been turned off! deleting...")
                    delete_ingress(arcade_name, narc_id, "public")

        elif load_balancer == "private":
            if private_alb_bool:
                # LB should exist
                if not lb_exists:
                    print(f"A PRIVATE load balancer has been turned on! creating...")
                    create_asteroid_ingress(arcade_name, asddata, "private")
            else:
                # LB should not exist
                if lb_exists:
                    print(f"A PRIVATE load balancer has been turned off! deleting...")
                    delete_ingress(arcade_name, narc_id, "private")

        else:
            logging.error(f"Invalid LB classification {load_balancer}")
    # End of check_loadbalancers_for_modification


# --------------------------------------------------------------------
#
# check_loadbalancers_for_update
#
# --------------------------------------------------------------------
def check_loadbalancers_for_update(arcade_name, asddata):
    """
    Inspect the details of a LB to see if any attributes have changed.
    If any part of the healthcheck is different between the ASD and the LB
    (path, port, protocol) then the healthcheck will be updated.  Likewise
    for attributes like the Nodeport of the service.
    """

    narc_id = asddata['service']
    asteroid_name = narc_id.replace('-', ' ').split()[1]
    asteroid_port = get_asteroid_port(narc_id=narc_id, asteroid=asteroid_name)

    # Use sane defaults if no data provided
    readiness_check_path = '/'
    readiness_check_scheme = 'HTTP'

    if "readiness_check_path" in asddata['containers'][0]:
        readiness_check_path = asddata['containers'][0]['readiness_check_path']

    if "readiness_check_https" in asddata['containers'][0]:
        if asddata['containers'][0]['readiness_check_https']:
            readiness_check_scheme = 'HTTPS'

    if 'public' in asddata['service_options']['load_balanced']:
        if asddata['service_options']['load_balanced']['public']:
            _update_lb(arcade_name, narc_id, 'public', asteroid_port, readiness_check_path, readiness_check_scheme)
    if 'private' in asddata['service_options']['load_balanced']:
        if asddata['service_options']['load_balanced']['private']:
            _update_lb(arcade_name, narc_id, 'private', asteroid_port, readiness_check_path, readiness_check_scheme)


# --------------------------------------------------------------------
#
# _update_lb
#
# --------------------------------------------------------------------
def _update_lb(arcade_name, narc_id, prefix, asteroid_port, readiness_check_path, readiness_check_scheme):
    """Inspect specific LB parameters vs ASD contents and make updates if differences"""
    # Check Listener
    #listeners = find_listner_arn(arcade_name, prefix)

    # Check Target Group for existance
    target_group_name = alb.create_unique_targetgroup_name(arcade_name, narc_id, prefix)
    target_group_info = get_asteroid_tg_info(target_group_name, narc_id)

    # CHECK AND UPDATE HEALTHCHECK

    # target_group_info[0] = TargetGroupArn
    # target_group_info[1] = LoadBalancerArns
    # target_group_info[2] = Port

    elb_client = boto3.client('elbv2')
    try:
        target_health = elb_client.describe_target_groups(TargetGroupArns=[target_group_info[0]])
    except ClientError as c_e:
        if c_e.response['Error']['Code'] == 'ValidationError':
            return '', '', ''
        if c_e.response['Error']['Code'] == 'TargetGroupNotFound':
            return '', '', ''
        logging.info(c_e)
        raise c_e

    target_healthcheck_path = target_health['TargetGroups'][0]['HealthCheckPath']
    target_healthcheck_port = target_health['TargetGroups'][0]['HealthCheckPort']
    target_healthcheck_scheme = target_health['TargetGroups'][0]['HealthCheckProtocol']

    update_health = False

    if target_healthcheck_path != readiness_check_path:
        print(f"The healthcheck path has changed! {readiness_check_path} will replace {target_healthcheck_path}")
        update_health = True
    if target_healthcheck_port != str(asteroid_port):
        print(f"The healthcheck port has changed! {asteroid_port} will replace {target_healthcheck_port}")
        update_health = True
    if target_healthcheck_scheme != readiness_check_scheme:
        print(f"The healthcheck scheme has changed! {readiness_check_scheme} will replace {target_healthcheck_scheme}")
        update_health = True

    if update_health:
        # Update the target group healthcheck
        try:
            response = elb_client.modify_target_group(TargetGroupArn=target_group_info[0],
                                                      HealthCheckPath=readiness_check_path,
                                                      HealthCheckPort=str(asteroid_port),
                                                      HealthCheckProtocol=target_healthcheck_scheme)
        except ClientError as c_e:
            print(c_e)
            logging.info(c_e)
            raise c_e


# --------------------------------------------------------------------
#
# _create_lb
#
# --------------------------------------------------------------------
def _create_lb(load_balanced, prefix, arcade_name, asd_data, tags, as_client, eks_asg, narc_id):
    """
    JCG-NOTE: Not sure about this, it does not return anything. 
    
    Args:
    Returns:
    """
    is_ok = False

    if load_balanced[prefix]:
        target_group_arn = create_asteroid_target_group(arcade_name=arcade_name,
                                                        prefix=prefix,
                                                        asd_data=asd_data,
                                                        tags=tags)

        try:
            as_response = as_client.attach_load_balancer_target_groups(
                AutoScalingGroupName=eks_asg,
                TargetGroupARNs=[target_group_arn])
            is_ok = True
        except ClientError as c_e:
            r_dict = common.handle_boto_error(c_e)
            logging.error(r_dict['msg'])
            is_ok = False

        if is_ok:
            create_alb_listener(arcade_name=arcade_name,
                                narc_id=narc_id,
                                target_grp_arn=target_group_arn,
                                prefix=prefix,
                                tags=tags)

            # TODO: IPTOOLS-520
            if prefix == 'public':
                authorize_alb_listener(arcade_name=arcade_name,
                                       narc_id=narc_id,
                                       prefix=prefix)
        # End of if
    # End of if
    # should return something here

    # End of _create_lb


# --------------------------------------------------------------------
#
# _delete_lb
#
# --------------------------------------------------------------------
def _delete_lb(load_balancer, arcade_name, narc_id, as_client, elb_client, eks_asg):
    """
    JCG-NOTE: Not sure about this.
    
    Args:
    Returns:
    """
    logging.info(load_balancer)
    target_group_name = alb.create_unique_targetgroup_name(arcade_name, narc_id, load_balancer)
    target_group_info = get_asteroid_tg_info(target_group_name, narc_id)
    logging.info(target_group_info)

    if target_group_info[0]:
        target_group_arn = target_group_info[0]
        target_group_port = target_group_info[2]
        if not target_group_info[1]:
            logging.warning(f"{load_balancer} load balancer for {target_group_name} does not exist.")

        loadbalancer_arn = target_group_info[1][0]

        _listener_arn = get_listener_arn(alb_arn=loadbalancer_arn, port=80)
        logging.info(_listener_arn)
        lb_rule_arn = find_narc_rule(_listener_arn, narc_id)
        logging.info(lb_rule_arn)
        if lb_rule_arn:
            delete_rule = elb_client.delete_rule(RuleArn=lb_rule_arn)
            logging.debug(delete_rule)

        # NLB like behavior only needed until rules engine is available for ALB
        nlb_listener_arn = get_listener_arn(alb_arn=loadbalancer_arn, port=target_group_port)
        logging.info(nlb_listener_arn)
        if nlb_listener_arn:
            delete_listener = elb_client.delete_listener(ListenerArn=nlb_listener_arn)
            logging.debug(delete_listener)

        # try except only necessary to cleanup after OLD asteroid only repo reconcile
        try:
            as_client.detach_load_balancer_target_groups(
                AutoScalingGroupName=eks_asg,
                TargetGroupARNs=[target_group_arn]
            )
        except ClientError as c_e:
            if not c_e.response['Error']['Code'] == 'ValidationError':
                logging.error(c_e)
                raise c_e

        try:
            delete_target_group = elb_client.delete_target_group(TargetGroupArn=target_group_arn)
            logging.debug(delete_target_group)
        except ClientError as c_e:
            r_dict = common.handle_boto_error(c_e)
            logging.error(r_dict['msg'])

        if load_balancer == 'public':
            revoke_alb_listener(arcade_name=arcade_name,
                                narc_id=narc_id,
                                asteroid_port=target_group_port,
                                prefix=load_balancer)
    # End of _delete_lb
