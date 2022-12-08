# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
alb -- ARCADE Load Balancer library
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'

import hashlib
import logging
import time
import boto3

from botocore.exceptions import ClientError

from arclib import common
from arclib import dns
from arclib import grv


# --------------------------------------------------------------------
#
# find_alb_arn
#
# --------------------------------------------------------------------
def find_alb_arn(alb_name: str) -> str:
    """
    Find the ALB Arn.

    Args:
        alb_name: name of alb

    Returns:
        ARN of the given alb, or empty string
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_load_balancers(Names=[alb_name])
        return response['LoadBalancers'][0]['LoadBalancerArn']
    except ClientError as c_e:
        return ''


# --------------------------------------------------------------------
#
# alb_create
#
# --------------------------------------------------------------------
def alb_create(grv_name: str,
               public: bool) -> dict:
    """
    Create an Application Load Balancer.

    Args:
        grv_name: gravitar name
        public: is this a public or internal alb

    Returns:
        dict of alb status response or exception dict
    """
    elb_client = boto3.client('elbv2')

    vpc_id = grv.get_vpc_id(grv_name)

    alb_dict = get_alb_dict(grv_name, public)

    subnets = grv.find_grv_subnets(grv_name, alb_dict['subnet_name'])

    if not subnets:
        return {'Code': 'failed',
                'Reason': f"{alb_dict['subnet_name']} subnets do not exists for {grv_name}"}

    alb_sgs = []
    alb_sg_id = grv.check_if_sg(alb_dict['sg_name'])

    if not alb_sg_id:
        alb_sg_id = grv.create_grv_sg(sg_name=alb_dict['sg_name'], vpc_id=vpc_id)

    alb_sgs.append(alb_sg_id)

    if alb_dict['subnet_name'] == 'wan':
        alb_nat_sg_id = grv.check_if_sg(f"nat.{grv_name}")
        alb_sgs.append(alb_nat_sg_id)

    response = elb_client.create_load_balancer(
        Name=alb_dict['name'],
        Subnets=subnets,
        SecurityGroups=alb_sgs,
        Scheme=alb_dict['scheme'],
        Tags=[
            {
                'Key': 'Name',
                'Value': alb_dict['name'],
            },
            {
                'Key': 'grv_name',
                'Value': grv_name,
            },
            {
                'Key': 'arcade_tool_provisioned',
                'Value': common.get_account_id(),
            },
        ],
        Type='application',
    )

    alb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    status = get_alb_status(alb_dict['name'])

    while 'provisioning' == status['State']['Code']:
        print(f"Waiting for the alb {alb_dict['name']} to be active")
        time.sleep(20)
        status = get_alb_status(alb_dict['name'])

    print(f"{alb_dict['name']} ALB Created with scheme {alb_dict['scheme']}")

    source = alb_dict['sg_name']
    target = status['DNSName']

    dns.add_arcade_cname(grv_name, source, target)

    # For all ALB's created, enable Desync mitigation mode.
    # Start by enabling the strictest mode, so services only receive requests that comply with RFC 7230
    modify_response = elb_client.modify_load_balancer_attributes(
        LoadBalancerArn=alb_arn,
        Attributes=[
            {
                'Key': 'routing.http.desync_mitigation_mode',
                'Value': 'strictest'
            },
            {
                'Key': 'routing.http.drop_invalid_header_fields.enabled',
                'Value': 'true'
            }
        ]
    )

    logging.info(modify_response)

    try:
        elb_client.create_listener(
            DefaultActions=[
                {
                    'Type': 'fixed-response',
                    'FixedResponseConfig': {
                        'StatusCode': '503',
                        'ContentType': 'text/plain'
                    },
                },
            ],
            LoadBalancerArn=alb_arn,
            Port=80,
            Protocol='HTTP',
        )
    except ClientError as c_e:
        return c_e.response


    return status


# --------------------------------------------------------------------
#
# delete_alb
#
# --------------------------------------------------------------------
def delete_alb(grv_name: str,
               public: bool) -> bool:
    """
    Delete an ALB.

    Args:
        grv_name: gravitar name to delete ALBs from
        public: is this a public or internal alb

    Returns:
    True if alb is deleted or not available, or False
    """
    elb_client = boto3.client('elbv2')

    alb_dict = get_alb_dict(grv_name, public)

    dns.delete_arcade_cname(grv_name, alb_dict['sg_name'])

    alb_arn = find_alb_arn(alb_dict['name'])

    if not alb_arn:
        return True

    response = elb_client.delete_load_balancer(LoadBalancerArn=alb_arn)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return False

    print(f"Deleted alb {alb_dict['name']}")
    while True:
        if not grv.check_if_sg(alb_dict['sg_name']):
            break
        try:
            grv.delete_grv_sg(alb_dict['sg_name'])
        except ClientError as c_e:
            if c_e.response['Error']['Code'] != 'DependencyViolation':
                raise c_e
        time.sleep(10)
    print(f"Deleted security group {alb_dict['sg_name']}")

    return True


# --------------------------------------------------------------------
#
# get_alb_status
#
# --------------------------------------------------------------------
def get_alb_status(alb_name: str) -> dict:
    """
    Get the alb status.

    Args:
        alb_name: alb name

    Returns:
        status dict of the response or exception dict
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_load_balancers(Names=[alb_name])
    except ClientError as c_e:
        logging.debug(c_e)
        return {}

    alb_status = response['LoadBalancers'][0]

    alb_attributes = elb_client.describe_load_balancer_attributes(LoadBalancerArn=alb_status['LoadBalancerArn'])

    alb_status['Attributes'] = alb_attributes['Attributes']
    logging.debug(alb_status)

    return alb_status


# --------------------------------------------------------------------
#
# find_sg_attached
#
# --------------------------------------------------------------------
def find_sg_attached(alb_name: str) -> str:
    """
    Return the security group attached to a alb.

    Args:
        alb_name: the name of the alb

    Returns:
        the id of security group, or empty string
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_load_balancers(Names=[alb_name])
        return response['LoadBalancers'][0]['SecurityGroups'][0]
    except ClientError as c_e:
        return ''


# --------------------------------------------------------------------
#
# alb_connect_sg
#
# --------------------------------------------------------------------
def alb_connect_sg(grv_name: str,
                   cluster_name: str,
                   public: bool) -> bool:
    """
    Connect gravitar security group to alb.

    Args:
        grv_name: gravitar name
        cluster_name: the name of eks cluster
        public: is this a public or internal alb

    Returns:
        success as a bool
    """
    elb_client = boto3.client('elbv2')
    alb_dict = get_alb_dict(grv_name, public)

    alb_arn = find_alb_arn(alb_dict['name'])
    if not alb_arn:
        return False

    eks_sg_filter = f"eks-cluster-sg-{cluster_name}"
    eks_sg_id = grv.check_if_sg(eks_sg_filter)

    if not eks_sg_id:
        return False

    response = elb_client.describe_load_balancers(LoadBalancerArns=[alb_arn])

    alb_sgs = response['LoadBalancers'][0]['SecurityGroups']
    if eks_sg_id in alb_sgs:
        return True

    alb_sgs.append(eks_sg_id)
    response = elb_client.set_security_groups(
        LoadBalancerArn=alb_arn,
        SecurityGroups=alb_sgs
    )

    return True


# --------------------------------------------------------------------
#
# is_sg_connected
#
# --------------------------------------------------------------------
def is_sg_connected(arcade_name: str,
                    sg_name: str,
                    public: bool) -> bool:
    """
    Is an ARCADE connected to the specified security group?

    Args:
        arcade_name: ARCADE name
        sg_name: the name of security group, partials are ok.
        public: is this a public or internal alb

    Returns:
        success as a bool
    """
    elb_client = boto3.client('elbv2')
    alb_dict = get_alb_dict(arcade_name, public)

    alb_arn = find_alb_arn(alb_dict['name'])
    if not alb_arn:
        return False

    sg_id = grv.check_if_sg(sg_name)

    if not sg_id:
        return False

    response = elb_client.describe_load_balancers(LoadBalancerArns=[alb_arn])

    alb_sgs = response['LoadBalancers'][0]['SecurityGroups']
    if sg_id in alb_sgs:
        return True

    return False


# --------------------------------------------------------------------
#
# alb_info
#
# --------------------------------------------------------------------
def alb_info(grv_name: str) -> dict:
    """
    Get alb information.

    Args:
        grv_name: gravitar name

    Returns:
        a dictionary containing information of load balancers and security groups
    """
    elb_client = boto3.client('elbv2')
    alb_public = get_alb_dict(grv_name, True)['name']
    alb_private = get_alb_dict(grv_name, False)['name']
    response = elb_client.describe_load_balancers(Names=[alb_public, alb_private])

    alb_info_dict = {'loadbalancers': {}}
    for loadbalancer in response["LoadBalancers"]:
        tags_response = elb_client.describe_tags(
            ResourceArns=[loadbalancer["LoadBalancerArn"]]
        )
        name = loadbalancer["LoadBalancerName"]
        alb_info_dict["loadbalancers"][name] = loadbalancer
        alb_info_dict["loadbalancers"][name]['Tags'] = tags_response['TagDescriptions'][0]['Tags']
        alb_info_dict["loadbalancers"][name]['TagSane'] = \
            common.aws_tags_dict(tags_response['TagDescriptions'][0]['Tags'])

    alb_sg_filter = f'_alb.{grv_name}'
    ec2_client = boto3.client('ec2')
    ec2_response = ec2_client.describe_security_groups(
        Filters=[
            {
                'Name': 'group-name',
                'Values': [alb_sg_filter]
            },
        ],
        DryRun=False
    )
    alb_info_dict['securitygroups'] = {}
    for securitygroup in ec2_response['SecurityGroups']:
        alb_info_dict['securitygroups'][securitygroup['GroupId']] = securitygroup
        alb_info_dict['securitygroups'][securitygroup['GroupId']]['TagSane'] = \
            common.aws_tags_dict(securitygroup['Tags'])
    return alb_info_dict


# --------------------------------------------------------------------
#
# get_alb_dict
#
# --------------------------------------------------------------------
def get_alb_dict(arcade_name: str,
                 public: bool) -> dict:
    """
    Return alb name dictionary for a gravitar and public flag.

    Args:
        arcade_name: the name of the ARCADE
        public: the bool flag indicating whether it is public or private

    Returns:
        A dictionary in the format of {name, sg_name, schema, subnets}
    """
    # albs have a specific naming scheme.
    # Security groups are based on unmodified ARCADE name for consistency
    # with ARCADE security groups.
    alb_arcade_name = arcade_name.replace('_', '').replace('.', '-')
    prefix = 'public' if public else 'private'
    scheme = 'internet-facing' if public else 'internal'
    subnet_name = 'wan' if public else 'core'

    alb_dict = {'name': f"{prefix}-{alb_arcade_name}",
                'sg_name': f'{prefix}_alb.{arcade_name}',
                'scheme': scheme,
                'subnet_name': subnet_name}
    return alb_dict


# --------------------------------------------------------------------
#
# create_unique_targetgroup_name
#
# --------------------------------------------------------------------
def create_unique_targetgroup_name(arcade_name: str, identifier: str, lb_prefix='private') -> str:
    """
    Return an unique name for a target group based
    on the ARCADE and an asteroid/galaga identifier.

    Args:
        arcade_name (str): the name of the arcade.
        identifier (str): a asteroid/galaga identifier(narc_id, galaga_id).
        lb_prefix (str): whether the lb is a private or public ARCADE LB.

    Returns:
        str: The unique 32 character target group name.
    """
    hash_data = f"{arcade_name}-{lb_prefix}-{identifier}"
    tg_prefix = f"{lb_prefix}-{arcade_name.replace('_', '').replace('.', '-')}"
    # tg_prefix1 = f"{lb_prefix[:3]}{arcade_name.replace('_', '').replace('.', '')}"
    # print(hashlib.sha512(tg_name.encode("utf-8")).hexdigest()[:32])
    # print(f"{tg_prefix1}{hashlib.sha512(tg_name.encode('utf-8')).hexdigest()}"[:32])
    logging.info(f"{tg_prefix}-{hashlib.sha512(hash_data.encode('utf-8')).hexdigest()}"[:32])
    return f"{tg_prefix}-{hashlib.sha512(hash_data.encode('utf-8')).hexdigest()}"[:32]


# --------------------------------------------------------------------
#
# create_arcade_target_group
#
# --------------------------------------------------------------------
def create_arcade_target_group(arcade_name: str,
                               prefix: str,
                               name: str,
                               protocol: str,
                               port: int,
                               path: str) -> str:
    """Create a target group for a public or private ALB to a target group.

    Creates a target group.

    Args:
        arcade_name (str): Arcade Name ex: icy_lake.grv
        prefix (str): public or private target group
        name (str): GSD/ASD name
        protocol (str): from the ASD/GSD
        port (int): from the ASD/GSD
        path (str): health check path

    Returns:
        [str]: Target group ARN
    """
    elb_client = boto3.client('elbv2')

    unique_id = f"{prefix}-{arcade_name}-{name}-{protocol}-{port}"
    tg_name = create_unique_targetgroup_name(arcade_name, unique_id, prefix)
    vpc_id = grv.get_vpc_id(grv_name=arcade_name)

    if 'HTTP' in protocol.upper():
        response = elb_client.create_target_group(
            Name=tg_name,
            Protocol=protocol.upper(),
            ProtocolVersion='HTTP1', # default
            Port=int(port), # port
            VpcId=vpc_id,
            HealthCheckProtocol=protocol.upper(),
            HealthCheckPort=str(port),
            HealthCheckEnabled=True,
            HealthCheckPath=path,
            HealthCheckIntervalSeconds=10,
            HealthCheckTimeoutSeconds=2,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={
                'HttpCode': '200',
            },
            TargetType='instance',
            Tags=[
                {
                    'Key': 'Name',
                    'Value': unique_id,
                },
                {
                    'Key': 'arcade_tool_provisioned',
                    'Value': common.get_account_id(),
                },
            ])
    else:
        response = elb_client.create_target_group(
            Name=tg_name,
            Protocol=protocol.upper(),
            Port=int(port), # port
            VpcId=vpc_id,
            HealthCheckEnabled=True,
            HealthCheckIntervalSeconds=10,
            TargetType='instance',
            Tags=[
                {
                    'Key': 'Name',
                    'Value': unique_id,
                },
                {
                    'Key': 'arcade_tool_provisioned',
                    'Value': common.get_account_id(),
                },
            ])

    return response['TargetGroups'][0]['TargetGroupArn']


# --------------------------------------------------------------------
#
# delete_arcade_target_group
#
# --------------------------------------------------------------------
def delete_arcade_target_group(arcade_name: str,
                               prefix: str,
                               name: str,
                               protocol: str,
                               port: int) -> dict:
    """Delete a target group for a public or private ALB to a target group.

    Delete a target group.

    Args:
        arcade_name (str): Arcade Name ex: icy_lake.grv
        prefix (str): public or private target group
        name (str): GSD/ASD name
        protocol (str): from the ASD/GSD
        port (int): from the ASD/GSD

    Returns:
        [dict]: empty if successful
    """
    elb_client = boto3.client('elbv2')

    unique_id = f"{prefix}-{arcade_name}-{name}-{protocol}-{port}"
    tg_name = create_unique_targetgroup_name(arcade_name, unique_id, prefix)
    target_group_info = get_arcade_tg_info(tg_name)
    if target_group_info.get('TargetGroupArn'):
        delete_target_group = elb_client.delete_target_group(TargetGroupArn=target_group_info['TargetGroupArn'])
        logging.debug(f"delete_target_group: {delete_target_group}")
    return {}


# --------------------------------------------------------------------
#
# create_arcade_alb_listener
#
# --------------------------------------------------------------------
def create_arcade_alb_listener(arcade_name: str,
                               prefix: str,
                               name: str,
                               target_group_arn: str):
    """Create ALB listener.

    Args:
        arcade_name (str): [Arcade Name]
        narc_id (str): [Id of The NARC ID]
        target_grp_arn (str): [Target Group ARN]
        prefix (str): public or private

    Returns:
        [dict]: [response]
    """
    elb_client = boto3.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    tg_port = target_group_info['Port']
    tg_protocol = target_group_info['Protocol']
    alb_name = f"{prefix}-{arcade_name.replace('_', '').replace('.', '-')}"
    alb_arn = find_alb_arn(alb_name=alb_name)
    asg_tg_name = f"{prefix}-{arcade_name}-{name}-{tg_protocol}-{tg_port}"

    response = elb_client.create_listener(
        LoadBalancerArn=alb_arn,
        Port=tg_port,
        Protocol=tg_protocol,
        DefaultActions=[
            {
                'Type': 'forward',
                'TargetGroupArn': target_group_arn,
            },
        ],
        Tags=[
            {
                'Key': 'Name',
                'Value': asg_tg_name,
            },
            {
                'Key': 'arcade_tool_provisioned',
                'Value': common.get_account_id(),
            },
        ]
    )

    return response['Listeners'][0]


# --------------------------------------------------------------------
#
# delete_arcade_alb_listener
#
# --------------------------------------------------------------------
def delete_arcade_alb_listener(arcade_name: str,
                               prefix: str,
                               path: str,
                               target_group_arn: str):
    """Create an ALB rule to forward to the Target Group.

    Args:
        arcade_name (str): [Arcade Name]
        prefix (str): [ALB Listener ARN]
        path (str): [Id of The NARC ID]
        target_grp_arn (str): [Target Group ARN]

    Returns:
        [dict]: [response]
    """
    elb_client = boto3.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    listener_arn = find_listener_arn(arcade_name, prefix, target_group_info['Port'])[0]
    response = elb_client.delete_listener(
        ListenerArn=listener_arn
    )

    return response


# --------------------------------------------------------------------
#
# get_arcade_tg_info
#
# --------------------------------------------------------------------
def get_arcade_tg_info(tg_name: str) -> dict:
    """Get Target Group information based on the NARC ID.

    Args:
        tg_name (str): ARCADE target group name (alb.create_unique_targetgroup_name format)

    Returns:
        dict: [TargetGroup ARN and ALB ARN and TargetGroup port]
    """
    elb_client = boto3.client('elbv2')
    try:
        response = elb_client.describe_target_groups(Names=[tg_name])
    except ClientError as c_e:
        if c_e.response['Error']['Code'] == 'ValidationError':
            return {}
        if c_e.response['Error']['Code'] == 'TargetGroupNotFound':
            return {}
        logging.info(c_e)
        raise c_e
    return response['TargetGroups'][0]


# --------------------------------------------------------------------
#
# attach_asg_to_tg
#
# --------------------------------------------------------------------
def attach_asg_to_tg(asg_name: str, target_group_arn: str) -> bool:
    """Get Target Group information based on the NARC ID.

    Args:
        tg_name (str): ARCADE target group name (alb.create_unique_targetgroup_name format)

    Returns:
        dict: [TargetGroup ARN and ALB ARN and TargetGroup port]
    """
    as_client = boto3.client('autoscaling')
    as_response = as_client.attach_load_balancer_target_groups(
                                                    AutoScalingGroupName=asg_name,
                                                    TargetGroupARNs=[target_group_arn]
                                                    )
    logging.debug(as_response)
    return True


# --------------------------------------------------------------------
#
# detach_asg_to_tg
#
# --------------------------------------------------------------------
def detach_asg_from_tg(asg_name: str, target_group_arn: str) -> bool:
    """Get Target Group information based on the NARC ID.

    Args:
        tg_name (str): ARCADE target group name (alb.create_unique_targetgroup_name format)

    Returns:
        dict: [TargetGroup ARN and ALB ARN and TargetGroup port]
    """
    as_client = boto3.client('autoscaling')
    as_response = as_client.detach_load_balancer_target_groups(
                                                    AutoScalingGroupName=asg_name,
                                                    TargetGroupARNs=[target_group_arn]
                                                    )
    logging.debug(as_response)
    return True


# --------------------------------------------------------------------
#
# find_listener_arn
#
# --------------------------------------------------------------------
def find_listener_arn(arcade_name:str, prefix: str, port=80) -> tuple:
    """Find the Listener ARN of a ALB.

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
        for listener in response['Listeners']:
            if listener['Port'] == port:
                return listener['ListenerArn'], listener['LoadBalancerArn']
    except ClientError as c_e:
        logging.info(c_e)
        return '', ''


# --------------------------------------------------------------------
#
# create_arcade_alb_rule
#
# --------------------------------------------------------------------
def create_arcade_alb_rule(arcade_name: str, prefix: str, name: str, target_group_arn: str):
    """Create an ALB rule to forward to the Target Group.

    Args:
        arcade_name (str): [Arcade Name]
        prefix (str): [ALB Listener ARN]
        name (str): [Id of The NARC ID]
        target_grp_arn (str): [Target Group ARN]

    Returns:
        [dict]: [response]
    """
    elb_client = boto3.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    listener_arn = find_listener_arn(arcade_name, prefix, target_group_info['Port'])[0]
    response = elb_client.create_rule(
        Priority=int(find_available_rule_priority(arcade_name='', listener_arn=listener_arn)),
        ListenerArn=listener_arn,
        Conditions=[
            {
                'Field': 'path-pattern',
                'Values': [
                    f'/{name}*'
                ]
            }
        ],
        Actions=[
            {
                'Type': 'forward',
                'TargetGroupArn': target_group_arn
            }
        ],
        Tags=[
            {
                'Key': 'Name',
                'Value': name
            },
            {
                'Key': 'arcade_tool_provisioned',
                'Value': common.get_account_id(),
            },
        ]
    )

    return response


# --------------------------------------------------------------------
#
# delete_arcade_alb_rule
#
# --------------------------------------------------------------------
def delete_arcade_alb_rule(arcade_name: str, prefix: str, path: str, target_group_arn: str):
    """Create an ALB rule to forward to the Target Group.

    Args:
        arcade_name (str): [Arcade Name]
        prefix (str): [ALB Listener ARN]
        path (str): [Id of The NARC ID]
        target_grp_arn (str): [Target Group ARN]

    Returns:
        [dict]: [response]
    """
    elb_client = boto3.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    listener_arn = find_listener_arn(arcade_name, prefix, target_group_info['Port'])[0]
    rule_arn = find_listener_rule(listener_arn, path)
    response = elb_client.delete_rule(
        RuleArn=rule_arn
    )

    return response


# --------------------------------------------------------------------
#
# find_available_rule_priority
#
# --------------------------------------------------------------------
def find_available_rule_priority(arcade_name: str, listener_arn: str):
    """Find the rule prioirity.

    Args:
        arcade_name (str): Name of the arcade
        listener_arn (str): Listener ARN

    Returns:
        [str]: [prioirty]
    """
    elb_client = boto3.client('elbv2')

    try:
        response = elb_client.describe_rules(
            ListenerArn=listener_arn,
        )
    except ClientError as c_e:
        logging.info(c_e)
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


# --------------------------------------------------------------------
#
# find_listener_rule
#
# --------------------------------------------------------------------
def find_listener_rule(listener_arn: str, name:str) -> str:
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
                if name in value:
                    return rule['RuleArn']
    return ''


# --------------------------------------------------------------------
#
# create_arcade_nlb
#
# --------------------------------------------------------------------
def create_arcade_nlb(grv_name: str,
                      public: bool) -> dict:
    """
    Create an Network Load Balancer.

    Args:
        grv_name: gravitar name
        public: is this a public or internal nlb

    Returns:
        dict of nlb status response or exception dict
    """
    elb_client = boto3.client('elbv2')

    vpc_id = grv.get_vpc_id(grv_name)

    nlb_dict = get_nlb_dict(grv_name, public)

    subnets = grv.find_grv_subnets(grv_name, nlb_dict['subnet_name'])

    if not subnets:
        return {'Code': 'failed',
                'Reason': f"{nlb_dict['subnet_name']} subnets do not exists for {grv_name}"}

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
                'Key': 'grv_name',
                'Value': grv_name,
            }
        ],
        Type='network',
    )

    nlb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    status = get_alb_status(nlb_dict['name'])

    while 'provisioning' == status['State']['Code']:
        print(f"Waiting for the nlb {nlb_dict['name']} to be active")
        time.sleep(20)
        status = get_alb_status(nlb_dict['name'])

    print(f"{nlb_dict['name']} NLB Created with scheme {nlb_dict['scheme']}")

    target = status['DNSName']
    source = f"{target.split('-')[0]}_nlb.{grv_name}"
    dns.add_arcade_cname(grv_name, source, target)

    return status


# --------------------------------------------------------------------
#
# delete_arcade_nlb
#
# --------------------------------------------------------------------
def delete_arcade_nlb(grv_name: str,
                      public: bool) -> bool:
    """
    Delete an NLB.

    Args:
        grv_name: gravitar name to delete NLBs from
        public: is this a public or internal nlb

    Returns:
    True if nlb is deleted or not available, or False
    """
    elb_client = boto3.client('elbv2')

    nlb_dict = get_nlb_dict(grv_name, public)

    dns_name = f"{nlb_dict['name'].split('-')[0]}_nlb.{grv_name}"
    dns.delete_arcade_cname(grv_name, dns_name)

    nlb_arn = find_alb_arn(nlb_dict['name'])

    if not nlb_arn:
        return True

    response = elb_client.delete_load_balancer(LoadBalancerArn=nlb_arn)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return False

    print(f"Deleted nlb {nlb_dict['name']}")

    return True


# --------------------------------------------------------------------
#
# get_nlb_info
#
# --------------------------------------------------------------------
def get_nlb_info(arcade_name: str) -> dict:
    """
    Get nlb information.

    Args:
        arcade_name: gravitar name

    Returns:
        a dictionary containing information of load balancers
    """
    elb_client = boto3.client('elbv2')
    nlb_public = get_nlb_dict(arcade_name, True)['name']
    nlb_private = get_nlb_dict(arcade_name, False)['name']
    response = elb_client.describe_load_balancers(Names=[nlb_public, nlb_private])

    nlb_info_dict = {'loadbalancers': {}}
    for loadbalancer in response["LoadBalancers"]:
        tags_response = elb_client.describe_tags(
            ResourceArns=[loadbalancer["LoadBalancerArn"]]
        )
        name = loadbalancer["LoadBalancerName"]
        nlb_info_dict["loadbalancers"][name] = loadbalancer
        nlb_info_dict["loadbalancers"][name]['Tags'] = tags_response['TagDescriptions'][0]['Tags']
        nlb_info_dict["loadbalancers"][name]['TagSane'] = \
            common.aws_tags_dict(tags_response['TagDescriptions'][0]['Tags'])

    return nlb_info_dict


# --------------------------------------------------------------------
#
# get_nlb_dict
#
# --------------------------------------------------------------------
def get_nlb_dict(arcade_name: str,
                 public: bool) -> dict:
    """
    Return nlb name dictionary for a gravitar and public flag.

    Args:
        arcade_name: the name of the ARCADE
        public: the bool flag indicating whether it is public or private

    Returns:
        A dictionary in the format of {name, schema, subnets}
    """
    # nlbs have a specific naming scheme.
    nlb_arcade_name = arcade_name.replace('_', '').replace('.', '-')
    prefix = 'public' if public else 'private'
    nlb_prefix = 'publicnlb' if public else 'privatenlb'
    scheme = 'internet-facing' if public else 'internal'
    subnet_name = 'wan' if public else 'core'

    nlb_dict = {'name': f"{nlb_prefix}-{nlb_arcade_name}",
                'scheme': scheme,
                'subnet_name': subnet_name}
    return nlb_dict


# --------------------------------------------------------------------
#
# get_list_lb
#
# --------------------------------------------------------------------
def get_list_lb() -> list:
    """Returns a List of all LoadBalancers Names

    Returns:
        list: List of LB Names
    """
    nlb = []
    nlb_client = boto3.client('elbv2')
    paginator = nlb_client.get_paginator('describe_load_balancers')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for lb in page['LoadBalancers']:
            nlb.append(lb['LoadBalancerName'])
    
    return nlb
