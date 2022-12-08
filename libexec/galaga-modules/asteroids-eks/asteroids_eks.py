# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
galagalib -- ARCADE write functions
"""

# @depends: python (>=3.7)
__version__ = '0.1.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""

import json
import logging
import os
import secrets
import time
import yaml

import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config, utils
from kubernetes.client.rest import ApiException

from arclib import alb
from arclib import common
from arclib import dns
from arclib import ecr
from arclib import eks
from arclib import grv
from arclib import k8s


ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}


ASSUME_NODEGROUP_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

ECR_ACCESS_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        }
    ]
}

# Permissions for non kube api service discovery
# Alternate service discovery uses AWS Parameter Store for data storage
# Node level access to AWS Parameter Store is required so the pods can access it
# We may be able to get away with Pod level access instead if we start supporting IAM at that level
PARAMETER_STORE_ACCESS = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:PutParameter",
                "ssm:DeleteParameter",
                "ssm:GetParameterHistory",
                "ssm:GetParametersByPath",
                "ssm:GetParameters",
                "ssm:GetParameter",
                "ssm:DeleteParameters",
                "ssm:DescribeParameters"
            ],
            "Resource": "*"
        }
    ]
}

def create_kubecost(arcade_name: str) -> bool:
    """Creates Kubecost for EKS

    Args:
        arcade_name (str): name of the arcade

    Returns:
        bool: True if created
    """
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    k8s_client = client.ApiClient()
    utils.create_from_yaml(k8s_client, "libexec/galaga-modules/asteroids-eks/kubecost_yaml/kubecost.yaml", namespace='kubecost')
    return True
    
    


# --------------------------------------------------------------------
#
# create_k8s_namespace
#
# --------------------------------------------------------------------

def create_namespace(namespace: str, arcade_name: str) -> bool:
    """Creates Kubernetes Namespace

    Args:
        namespace (str): name of the namespace
        arcade_name (str): name of the arcade

    Returns:
        bool: Returns True if the namespace was created, False if there is a failure
    """
    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False
    
    core_v1 = client.CoreV1Api()
    try:
        core_v1.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace)))
        return True
    except ApiException:
        return False

# --------------------------------------------------------------------
#
# create_arcade_alb
#
# --------------------------------------------------------------------
def create_arcade_alb(arcade_name: str,
                      public: bool) -> dict:
    """
    Create an Application Load Balancer.

    Args:
        arcade_name: ARCADE name
        public: is this a public or internal alb

    Returns:
        dict of alb status response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')

    vpc_id = grv.get_vpc_id(arcade_name)

    alb_dict = alb.get_alb_dict(arcade_name, public)

    subnets = grv.find_grv_subnets(arcade_name, alb_dict['subnet_name'])

    if not subnets:
        return {'Code': 'failed',
                'Reason': f"{alb_dict['subnet_name']} subnets do not exists for {arcade_name}"}

    alb_sgs = []
    alb_sg_id = grv.check_if_sg(alb_dict['sg_name'])

    if not alb_sg_id:
        alb_sg_id = grv.create_grv_sg(sg_name=alb_dict['sg_name'], vpc_id=vpc_id)

    alb_sgs.append(alb_sg_id)

    if alb_dict['subnet_name'] == 'wan':
        alb_nat_sg_id = grv.check_if_sg(f"nat.{arcade_name}")
        alb_sgs.append(alb_nat_sg_id)

    print(f"Creating Asteroids ALB {alb_dict['name']}...")
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
                'Value': arcade_name,
            },
            {
                'Key': 'grv_create_session_id',
                'Value': grv.validate_create_id(arcade_name),
            },
            {
                'Key': 'arcade_tool_provisioned',
                'Value': common.get_account_id(),
            },
        ],
        Type='application',
    )

    alb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    status = alb.get_alb_status(alb_dict['name'])

    while 'provisioning' == status['State']['Code']:
        print(f"Waiting for the Asteroids ALB {alb_dict['name']} to be active")
        time.sleep(20)
        status = alb.get_alb_status(alb_dict['name'])

    print(f"Asteroids {alb_dict['name']} ALB Created with scheme {alb_dict['scheme']}")

    source = alb_dict['sg_name']
    target = status['DNSName']
    dns.add_arcade_cname(arcade_name, source, target)

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
# delete_arcade_alb
#
# --------------------------------------------------------------------
def delete_arcade_alb(arcade_name: str,
                      public: bool) -> bool:
    """
    Delete an ALB.

    Args:
        arcade_name: ARCADE name to delete ALBs from
        public: is this a public or internal alb

    Returns:
    True if alb is deleted or not available, or False
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')

    alb_dict = alb.get_alb_dict(arcade_name, public)

    dns.delete_arcade_cname(arcade_name, alb_dict['sg_name'])

    alb_arn = alb.find_alb_arn(alb_dict['name'])

    if not alb_arn:
        return True

    response = elb_client.delete_load_balancer(LoadBalancerArn=alb_arn)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return False

    print(f"Deleted Asteroids ALB {alb_dict['name']}")
    while True:
        if not grv.check_if_sg(alb_dict['sg_name']):
            break
        try:
            grv.delete_grv_sg(alb_dict['sg_name'])
        except ClientError as c_e:
            if c_e.response['Error']['Code'] != 'DependencyViolation':
                raise c_e
        time.sleep(10)
    print(f"Deleted Asteroids ALB security group {alb_dict['sg_name']}")

    return True


# --------------------------------------------------------------------
#
# connect_sg_to_alb
#
# --------------------------------------------------------------------
def connect_sg_to_alb(arcade_name: str,
                      cluster_name: str,
                      public: bool) -> bool:
    """
    Connect gravitar security group to alb.

    Args:
        arcade_name: ARCADE name
        cluster_name: the name of eks cluster
        public: is this a public or internal alb

    Returns:
        success as a bool
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')
    alb_dict = alb.get_alb_dict(arcade_name, public)

    alb_arn = alb.find_alb_arn(alb_dict['name'])
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
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')

    unique_id = f"{prefix}-{arcade_name}-{name}-{protocol}-{port}"
    tg_name = alb.create_unique_targetgroup_name(arcade_name, unique_id, prefix)
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
                    'Key': 'grv_create_session_id',
                    'Value': grv.validate_create_id(arcade_name),
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
                    'Key': 'grv_create_session_id',
                    'Value': grv.validate_create_id(arcade_name),
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
                               port: int) -> str:
    """Delete a target group for a public or private ALB to a target group.

    Delete a target group.

    Args:
        arcade_name (str): Arcade Name ex: icy_lake.grv
        prefix (str): public or private target group
        name (str): GSD/ASD name
        protocol (str): from the ASD/GSD
        port (int): from the ASD/GSD

    Returns:
        [str]: Target group ARN
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')

    unique_id = f"{prefix}-{arcade_name}-{name}-{protocol}-{port}"
    tg_name = alb.create_unique_targetgroup_name(arcade_name, unique_id, prefix)
    target_group_info = alb.get_arcade_tg_info(tg_name)
    delete_target_group = elb_client.delete_target_group(TargetGroupArn=target_group_info['TargetGroupArn'])
    logging.debug(f"delete_target_group: {delete_target_group}")
    return delete_target_group


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
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    tg_port = target_group_info['Port']
    tg_protocol = target_group_info['Protocol']
    alb_name = f"{prefix}-{arcade_name.replace('_', '').replace('.', '-')}"
    alb_arn = alb.find_alb_arn(alb_name=alb_name)
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
                'Key': 'grv_create_session_id',
                'Value': grv.validate_create_id(arcade_name),
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
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    listener_arn = alb.find_listener_arn(arcade_name, prefix, target_group_info['Port'])[0]
    response = elb_client.delete_listener(
        ListenerArn=listener_arn
    )

    return response


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
    arcade_session = boto3.session.Session()
    as_client = arcade_session.client('autoscaling')
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
    arcade_session = boto3.session.Session()
    as_client = arcade_session.client('autoscaling')
    as_response = as_client.detach_load_balancer_target_groups(
                                                    AutoScalingGroupName=asg_name,
                                                    TargetGroupARNs=[target_group_arn]
                                                    )
    logging.debug(as_response)
    return True


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
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    listener_arn = alb.find_listener_arn(arcade_name, prefix, target_group_info['Port'])[0]
    response = elb_client.create_rule(
        Priority=int(alb.find_available_rule_priority(arcade_name='', listener_arn=listener_arn)),
        ListenerArn=listener_arn,
        Conditions=[
            {
                'Field': 'path-pattern',
                'Values': [
                    f"/{name}*"
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
                'Key': 'grv_create_session_id',
                'Value': grv.validate_create_id(arcade_name),
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
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    elb_client = arcade_session.client('elbv2')
    target_group_info = elb_client.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
    listener_arn = alb.find_listener_arn(arcade_name, prefix, target_group_info['Port'])[0]
    rule_arn = alb.find_listener_rule(listener_arn, path)
    response = elb_client.delete_rule(
        RuleArn=rule_arn
    )

    return response


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
# rds_default_creds
#
# --------------------------------------------------------------------
def rds_default_creds(arcade_name: str,
                      name='rds_default_credentials',
                      length=12):
    """
    Generates Default RDS creds for secrets manager per arcade

    Args:
        arcade_name (str): [arcade name]
        name (str, optional): [name of the secret]. Defaults to 'rds_default_credentials'.
        length (int, optional): [length of password]. Defaults to 12.

    Returns:
        [bool]: [True if Secret is created, False if the Secret failed to create]
    """
    arcade_trim = arcade_name.split('.')[0]
    create_p = secrets.token_urlsafe(length)
    s_value = {
        'username': f"{arcade_trim}_admin",
        'password': create_p
    }

    try:
        create_rds_cred = create_secret(
            arcade_name=arcade_name,
            name=name,
            secret_value=s_value
        )
    except ClientError as c_e:
        if c_e.response['Error']['Code'] == 'ResourceExistsException':
            logging.info("RDS Credentials already exist")
            return True
        print(c_e)
        logging.info(c_e)
        return False

    logging.info("Default RDS Credentials are set")
    return True


# --------------------------------------------------------------------
#
# create_secret
#
# --------------------------------------------------------------------
def create_secret(arcade_name: str,
                  name: str,
                  secret_value,
                  versions=None):
    """
    Creates a Secret In AWS Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [Name of the secret]
        secret_value : [The secret]
        versions ([type], optional): [description]. Defaults to None.

    Returns:
        [dict]: [Returns the ARN and Secret Name]
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    sm_client = arcade_session.client('secretsmanager')
    kwargs = {"Name": f"{arcade_name}/{name}",
              "Tags": [
                {
                    'Key': 'creator',
                    'Value': grv.aws_whoami(),
                },
                {
                    'Key': 'grv_name',
                    'Value': arcade_name,
                },
                {
                    'Key': 'grv_create_session_id',
                    'Value': grv.validate_create_id(arcade_name),
                },
                {
                    'Key': 'arcade_tool_provisioned',
                    'Value': common.get_account_id(),
                },
              ]
             }

    if isinstance(secret_value, dict):
        kwargs['SecretString'] = json.dumps(secret_value)

    elif isinstance(secret_value, str):
        kwargs['SecretString'] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs['SecretBinary'] = secret_value

    if versions is None:
        response = sm_client.create_secret(**kwargs)
        logging.info(response)
    else:
        response = sm_client.create_secret(**kwargs)
        logging.info(response)
        response = update_secret_version(
            arcade_name=arcade_name,
            name=name,
            secret_value=secret_value,
            versions=[versions])

    return {'SecretName': response['Name'], 'SecretARN': response['ARN']}


# --------------------------------------------------------------------
#
# update_secret_version
#
# --------------------------------------------------------------------
def update_secret_version(arcade_name: str,
                          name: str,
                          secret_value: str,
                          versions=None):
    """
    Puts Value with Version in Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [Name of the secret]
        secret_value (str): [The secret]
        versions ([type], optional): [A version for the secret]. Defaults to None.
        ex: update_secret_version(arcade_name="my-test-arcade-str", name="my-test-secret-str", secret_value="test-secret-str-new-version", versions=["new-version"])

    Returns:
        [dict]: [aws api return]
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    sm_client = arcade_session.client("secretsmanager")
    kwargs = {"SecretId": f"{arcade_name}/{name}"}

    if isinstance(secret_value, dict):
        kwargs['SecretString'] = json.dumps(secret_value)

    elif isinstance(secret_value, str):
        kwargs['SecretString'] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs['SecretBinary'] = secret_value

    if versions is not None:
        kwargs['VersionStages'] = versions

    response = sm_client.put_secret_value(**kwargs)

    return response


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
                },
            ]
        )
    except ClientError as c_e:
        logging.debug(c_e)
        return ""

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
# create_eks
#
# --------------------------------------------------------------------
def create_eks(arcade_name: str,
               cluster_prefix: str,
               eks_version: str = '1.20') -> dict:
    """
    Create an EKS cluster.

    Args:
        arcade_name: ARCADE name
        cluster_prefix: the prefix of a cluster
        eks_version: eks version. Defaults to '1.20'.

    Returns:
        status dict of the response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"

    status = eks.get_eks_status(eks_name)

    if 'Error' in status:
        # Create the cluster when it does not exist.
        eks_cluster_role = 'EKSClusterRole'
        eks_cluster_policy_arns = ['arn:aws:iam::aws:policy/AmazonEKSClusterPolicy']
        eks_sg_name = f"{cluster_prefix}_eks.{arcade_name}"

        vpc_id = grv.get_vpc_id(arcade_name)
        eks_sg_id = grv.check_if_sg(eks_sg_name)
        if not eks_sg_id:
            eks_sg_id = grv.create_grv_sg(sg_name=eks_sg_name, vpc_id=vpc_id)

        eks_client = arcade_session.client('eks')

        role_status = grv.find_role(eks_cluster_role)

        if role_status:
            role_to_use = role_status['Role']['Arn']
        else:
            role_to_use = create_role(role_name=eks_cluster_role,
                                      policy_arns=eks_cluster_policy_arns,
                                      assume_policy=ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT,
                                      custom_policy=ECR_ACCESS_POLICY_DOCUMENT)

        core_subnets = grv.find_grv_subnets(arcade_name, "core")
        print(f"Creating EKS cluster {eks_name}...")
        response = eks_client.create_cluster(
            name=eks_name.replace(".", "-"),
            version=eks_version,
            roleArn=role_to_use,
            resourcesVpcConfig={
                'subnetIds': core_subnets,
                'securityGroupIds': [eks_sg_id],
                'endpointPublicAccess': True
            },
            tags={
                'grv_name': arcade_name,
                'grv_create_session_id': grv.validate_create_id(arcade_name),
                'creator': grv.aws_whoami(),
                'arcade_tool_provisioned': common.get_account_id(),
            }
        )

        status = response['cluster']

        while 'CREATING' == status['status']:
            print(f"Waiting for the EKS cluster {eks_name} to be active.")
            time.sleep(120)
            status = eks.get_eks_status(eks_name)

        print(f"EKS cluster {eks_name} is created!")
    elif 'CREATING' == status['status']:
        while 'CREATING' == status['status']:
            print(f"Waiting for the EKS cluster {eks_name} to be active.")
            time.sleep(120)
            status = eks.get_eks_status(eks_name)
    else:
        print(f"EKS cluster {eks_name} already exists, status: {status['status']}")

    return status


# --------------------------------------------------------------------
#
# update_eks_version
#
# --------------------------------------------------------------------
def update_eks_version(arcade_name: str,
                       cluster_prefix: str,
                       eks_version: str = '1.20') -> dict:
    """
    Update an EKS cluster version.

    Args:
        arcade_name: ARCADE name
        cluster_prefix: the prefix of a cluster
        eks_version: eks version. Defaults to '1.20'.

    Returns:
        status dict of the response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"

    status = eks.get_eks_status(eks_name)

    if 'ACTIVE' in status.get('status'):
        eks_client = arcade_session.client('eks')

        response = eks_client.update_cluster_version(
            name=eks_name.replace(".", "-"),
            version=eks_version,
        )

        # update_id = response['update']['id']
        time.sleep(60)
        status = eks.get_eks_status(eks_name)

        while 'UPDATING' == status['status']:
            print(f"Waiting for the EKS cluster {eks_name} to update.")
            time.sleep(60)
            status = eks.get_eks_status(eks_name)

        print(f"EKS cluster {eks_name} is updated!")
    elif 'UPDATING' == status['status']:
        while 'UPDATING' == status['status']:
            print(f"Waiting for the EKS cluster {eks_name} to update.")
            time.sleep(60)
            status = eks.get_eks_status(eks_name)
        print(f"EKS cluster {eks_name} is updated!")
    else:
        print(f"EKS cluster {eks_name} is not ACTIVE, status: {status['status']}")

    return status


# --------------------------------------------------------------------
#
# update_eks_nodegroup_version
#
# --------------------------------------------------------------------
def update_eks_nodegroup_version(arcade_name: str,
                                 cluster_prefix: str,
                                 nodegroup: str,
                                 eks_version: str = None) -> dict:
    """
    Update an EKS nodegroup version.

    Args:
        arcade_name: ARCADE name
        cluster_prefix: the prefix of a cluster
        nodegroup: the nodegroup to update
        eks_version: eks version. Defaults to cluster version.

    Returns:
        status dict of the response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_client = arcade_session.client('eks')
    eks_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"

    eks_info = eks.get_eks_info(eks_name)
    if not eks_version:
        eks_version = eks_info['version']

    if 'ACTIVE' in eks_info.get('status'):
        nodegroup_status = eks.get_eks_nodegroup_status(eks_name, nodegroup)
        if 'ACTIVE' in nodegroup_status.get('status'):
            response = eks_client.update_nodegroup_version(
                                    clusterName=eks_name.replace(".", "-"),
                                    nodegroupName=nodegroup,
                                    version=eks_version,
                                    )

            # update_id = response['update']['id']
            nodegroup_status = eks.get_eks_nodegroup_status(eks_name, nodegroup)

            while 'UPDATING' == nodegroup_status['status']:
                print(f"Waiting for the EKS nodegroup {nodegroup} to update version.")
                time.sleep(120)
                nodegroup_status = eks.get_eks_nodegroup_status(eks_name, nodegroup)

            print(f"EKS nodegroup {nodegroup} version is updated!")
        elif 'UPDATING' == nodegroup_status['status']:
            while 'UPDATING' == nodegroup_status['status']:
                print(f"Waiting for the EKS nodegroup {eks_name} to update version.")
                time.sleep(120)
                status = eks.get_eks_status(eks_name)
            print(f"EKS nodegroup {nodegroup} version is updated!")
    else:
        print(f"EKS cluster {eks_name} is not ACTIVE, status: {status['status']}")

    return nodegroup_status


# --------------------------------------------------------------------
#
# delete_eks
#
# --------------------------------------------------------------------
def delete_eks(arcade_name: str,
               cluster_prefix: str) -> dict:
    """
    Delete EKS cluster with given cluster name.

    Args:
        arcade_name: ARCADE name
        cluster_prefix: name of the eks to be deleted

    Returns:
        status dict of the response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"
    eks_sg_name = f"{cluster_prefix}_eks.{arcade_name}"

    eks_info = eks.get_eks_info(eks_name)
    if eks_info.get('nodegroups'):
        print('EKS nodegroups still exist.')
        print('Manually destroy nodegroups or update the asteroids-eks GSD.')
        return {'Error': {'Code': 'NodegroupsStillExist'}}

    status = eks.get_eks_status(eks_name)

    if 'Error' in status:
        grv.delete_grv_sg(eks_sg_name)
        return status

    if 'DELETING' == status['status']:
        while 'Error' not in status and 'DELETING' == status['status']:
            print(f"Waiting for EKS cluster {eks_name} to be deleted.")
            time.sleep(30)
            status = eks.get_eks_status(eks_name)
    else:
        eks_client = arcade_session.client('eks')
        print(f"Deleting EKS cluster {eks_name}...")
        response = eks_client.delete_cluster(name=eks_name)
        status = response['cluster']

        while 'Error' not in status and 'DELETING' == status['status']:
            print(f"Waiting for EKS cluster {eks_name} to be deleted.")
            time.sleep(30)
            status = eks.get_eks_status(eks_name)

    grv.delete_grv_sg(eks_sg_name)

    return status


# --------------------------------------------------------------------
#
# create_eks_nodegroup
#
# --------------------------------------------------------------------
def create_eks_nodegroup(arcade_name: str,
                         cluster_prefix: str,
                         nodegroup_data: dict) -> dict:
    """
    Create an EKS nodegroup for the cluster.

    Args:
        arcade_name: ARCADE name
        cluster_prefix: the prefix of a cluster
        nodegroup_data: the data of the nodegroup

    Returns:
        status dict of the response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"
    eks_nodegroup_name = f"{nodegroup_data['nodegroup_prefix']}_nodegroup-{arcade_name.replace('.', '-')}"
    size = nodegroup_data['size']
    instance_type = nodegroup_data['instance_type']
    nodes = nodegroup_data['nodes']
    max_nodes = nodegroup_data.get('max_nodes')
    if max_nodes is None or max_nodes < nodes:
        max_nodes = nodes

    status = eks.get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    if 'Error' in status:
        eks_node_instance_role = 'EKSNodeInstanceRole'
        eks_node_instance_policy_arns = ['arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
                                         'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
                                         'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly']
                                         # enable SSM to EKS nodes.
                                         # 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'

        nodegroup_subnets = grv.find_grv_subnets(arcade_name, "core")
        # Use default security group for now.
        # Only needed for SSH.
        # ssh_net_sg_id = grv.check_if_sg(arcade_name)

        role_status = grv.find_role(eks_node_instance_role)

        if role_status:
            role_to_use = role_status['Role']['Arn']
        else:
            role_to_use = create_role(role_name=eks_node_instance_role,
                                          policy_arns=eks_node_instance_policy_arns,
                                          assume_policy=ASSUME_NODEGROUP_ROLE_POLICY_DOCUMENT,
                                          custom_policy=PARAMETER_STORE_ACCESS)

        eks_client = arcade_session.client('eks')
        print(f"Creating EKS nodegroup {eks_nodegroup_name}...")
        response = eks_client.create_nodegroup(
            clusterName=eks_name,
            nodegroupName=eks_nodegroup_name,
            scalingConfig={
                'minSize': nodes,
                'maxSize': max_nodes,
                'desiredSize': nodes
            },
            diskSize=size,
            subnets=nodegroup_subnets,
            instanceTypes=[instance_type],
            amiType='AL2_x86_64',
            nodeRole=role_to_use,
            tags={
                'grv_name': arcade_name,
                'grv_create_session_id': grv.validate_create_id(arcade_name),
                'creator': grv.aws_whoami(),
                'arcade_tool_provisioned': common.get_account_id(),
            },
            capacityType='ON_DEMAND',
        )
            # SSH configuration if ever needed again.
            # remoteAccess={
            #     'ec2SshKey': f"bootstrap.{arcade_name}",
            #     'sourceSecurityGroups': [ssh_net_sg_id]
            # },

        status = response['nodegroup']

        while 'CREATING' == status['status']:
            print(f"Waiting for EKS nodegroup {eks_nodegroup_name} to be active")
            time.sleep(120)
            status = eks.get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    elif 'CREATING' == status['status']:
        while 'CREATING' == status['status']:
            print(f"Waiting for EKS nodegroup {eks_nodegroup_name} to be active")
            time.sleep(120)
            status = eks.get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    return status


# --------------------------------------------------------------------
#
# update_eks_nodegroup_config
#
# --------------------------------------------------------------------
def update_eks_nodegroup_config(arcade_name: str,
                                cluster_prefix: str,
                                nodegroup_name: str,
                                nodegroup_data: dict) -> dict:
    """
    Update an EKS nodegroup for the cluster.

    Args:
        arcade_name: ARCADE name
        cluster_prefix: the prefix of a cluster
        nodegroup_data: the data of the nodegroup

    Returns:
        status dict of the response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"

    # size = nodegroup_data['size']
    # instance_type = nodegroup_data['instance_type']
    nodes = nodegroup_data['nodes']
    max_nodes = nodegroup_data.get('max_nodes')
    if max_nodes is None or max_nodes < nodes:
        print('nodes is greater than max_nodes.')
        print('setting max_nodes to nodes.')
        max_nodes = nodes

    nodegroup_info = eks.get_eks_nodegroup_info(eks_name, nodegroup_name)

    if 'ACTIVE' in nodegroup_info.get('status'):
        current_max_nodes = nodegroup_info['scalingConfig']['maxSize']
        current_nodes = nodegroup_info['scalingConfig']['desiredSize']
        if max_nodes > current_max_nodes or nodes > current_nodes:
            eks_client = arcade_session.client('eks')
            print(f"Updating EKS nodegroup {nodegroup_name}...")
            response = eks_client.update_nodegroup_config(
                clusterName=eks_name,
                nodegroupName=nodegroup_name,
                scalingConfig={
                    'minSize': nodes,
                    'maxSize': max_nodes,
                    'desiredSize': nodes
                }
            )

            # status = response['update']
            nodegroup_info = eks.get_eks_nodegroup_info(eks_name, nodegroup_name)

            while 'UPDATING' == nodegroup_info.get('status'):
                print(f"Waiting for EKS nodegroup {nodegroup_name} to be active")
                time.sleep(60)
                nodegroup_info = eks.get_eks_nodegroup_info(eks_name, nodegroup_name)

    elif 'UPDATING' == nodegroup_info.get('status'):
        while 'UPDATING' == nodegroup_info.get('status'):
            print(f"Waiting for EKS nodegroup {nodegroup_name} to be active")
            time.sleep(60)
            nodegroup_info = eks.get_eks_nodegroup_info(eks_name, nodegroup_name)

    return nodegroup_info.get('status')


# --------------------------------------------------------------------
#
# delete_eks_nodegroup
#
# --------------------------------------------------------------------
def delete_eks_nodegroup(arcade_name: str,
                         cluster_prefix: str,
                         nodegroup_data) -> dict:
    """
    Delete eks nodegroup for the cluster.

    Args:
        arcade_name: the name of arcade_name
        cluster_prefix: the prefix of cluster
        nodegroup_data: the data of the nodegroup

    Returns:
        status dict of the response or exception dict
    """
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"
    eks_nodegroup_name = f"{nodegroup_data['nodegroup_prefix']}_nodegroup-{arcade_name.replace('.', '-')}"

    status = eks.get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    if 'Error' in status:
        return status

    print(f"Deleting EKS nodegroup {eks_nodegroup_name}...")
    if 'DELETING' == status['status']:
        while 'Error' not in status and 'DELETING' == status['status']:
            print(f"Waiting for EKS nodegroup {eks_nodegroup_name} to be deleted.")
            time.sleep(30)
            status = eks.get_eks_nodegroup_status(eks_name, eks_nodegroup_name)
            logging.debug(status)
    else:
        eks_client = arcade_session.client('eks')
        response = eks_client.delete_nodegroup(
            clusterName=eks_name,
            nodegroupName=eks_nodegroup_name
        )

        status = response['nodegroup']

        while 'Error' not in status and 'DELETING' == status['status']:
            print(f"Waiting for EKS nodegroup {eks_nodegroup_name} to be deleted.")
            time.sleep(30)
            status = eks.get_eks_nodegroup_status(eks_name, eks_nodegroup_name)
            logging.debug(status)

    if status.get('Error') and status['Error']['Code'] == 'ResourceNotFoundException':
        status['status'] = 'DELETED'

    logging.debug(status)

    return status


# --------------------------------------------------------------------
#
# apply_awsauth_configmap
#
# --------------------------------------------------------------------
def apply_awsauth_configmap(arcade_name: str,
                            cluster_prefix: str):
    """
    Apply AWS auth configmap to the EKS context.

    Args:
        cluster_prefix: the prefix of a cluster
        arcade_name: arcade_name name

    Returns:
        bool
    """
    if not cluster_prefix or not arcade_name:
        return False

    cluster_name = f"{cluster_prefix}-{arcade_name.replace('.', '-')}"
    arcade_session = common.setup_arcade_session(arcade_name=arcade_name)
    eks_admin_role = 'EKSAdminRole'
    tmp_dir = os.getenv("ATMP", '/tmp')

    # This is used when the EKS cluster is initially Created
    # use load_arcade_k8s_config for all other k8s configuration
    eks_client = arcade_session.client('eks')
    try:
        response = eks_client.describe_cluster(name=cluster_name)
    except ClientError as c_e:
        logging.warning(f"Cluster error: {c_e}")
        return False
    context_cert_data = response["cluster"]["certificateAuthority"]["data"]
    context_server = response["cluster"]["endpoint"]
    context_arn = response["cluster"]["arn"]
    context_name = response["cluster"]["name"]
    context_region = context_arn.split(":")[3]

    iam_client = arcade_session.client('iam')
    role_res = iam_client.get_role(RoleName=eks_admin_role)
    eksadminrolearn = role_res['Role']['Arn']

    context_dict_yaml = f"""
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
      args:
      - --region
      - {context_region}
      - eks
      - get-token
      - --cluster-name
      - {context_name}
      command: aws
"""

    contexts = {}
    contexts['creator'] = yaml.safe_load(context_dict_yaml)
    contexts['role'] = yaml.safe_load(context_dict_yaml)
    contexts['role']['users'][0]['user']['exec']['args'].append('--role-arn')
    contexts['role']['users'][0]['user']['exec']['args'].append(eksadminrolearn)

    grv_info = grv.get_gravitar_info(arcade_name)
    vpc_id = list(grv_info['vpc'].keys())[0]
    owner_id = grv_info['vpc'][vpc_id]['OwnerId']

    eks_node_instance_role = 'EKSNodeInstanceRole'

    # 4 braces are necessary to escape formatted text braces.
    awsauth_configmap_yaml = f"""
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: arn:aws:iam::{owner_id}:role/{eks_node_instance_role}
      username: system:node:{{{{EC2PrivateDNSName}}}}
      groups:
        - system:bootstrappers
        - system:nodes
    - rolearn: arn:aws:iam::{owner_id}:role/Amazon{eks_admin_role}
      username: Amazon{eks_admin_role}:{{{{SessionName}}}}
      groups:
        - system:masters
    - rolearn: arn:aws:iam::{owner_id}:role/{eks_admin_role}
      username: {eks_admin_role}:{{{{SessionName}}}}
      groups:
        - system:masters
"""

    awsauth_configmap = yaml.safe_load(awsauth_configmap_yaml)

    for entity in ['role', 'creator']:
        context_file_name = f"{tmp_dir}/{entity}-context.yaml"
        with open(context_file_name, "w", encoding="utf-8") as context_file:
            yaml.dump(contexts[entity], context_file, default_flow_style=False)
        config.load_kube_config(config_file=context_file_name)
        core_v1 = client.CoreV1Api()

        try:
            response = core_v1.create_namespaced_config_map(
                namespace="kube-system",
                body=awsauth_configmap,
            )
            logging.info(f"Created aws-auth ConfigMap by {entity}")
            return True
        except ApiException as api_error:
            if api_error.status == 409:
                api_response = core_v1.replace_namespaced_config_map(
                    name=awsauth_configmap['metadata']['name'],
                    namespace=awsauth_configmap['metadata']['namespace'],
                    body=awsauth_configmap,
                )
                logging.info(f"Replaced aws-auth ConfigMap by {entity}")
                return True
            if api_error.status == 401:
                logging.debug(api_error)
                continue
            logging.warning(api_error)
            raise api_error

    return False


# --------------------------------------------------------------------
#
# apply_asteroids_fluentd_daemonset
#
# --------------------------------------------------------------------
def apply_asteroids_fluentd_daemonset(arcade_name: str,
                                      cluster_prefix: str) -> bool:
    """
    Apply ServiceAccount, ClusterRole, ClusterRoleBinding, and DaemonSet for
    fluentd node logging to log-relay.

    Args:
        arcade_name: arcade_name name
        cluster_prefix: the prefix of a cluster

    Returns:
        bool
    """
    if not cluster_prefix or not arcade_name:
        return False

    arcade_domain = arcade_name.replace('_', '-')
    arcade_safe_name = arcade_name.replace('_', '').replace('.', '-')
    asg_name = f"{cluster_prefix}.{arcade_domain}"
    daemonset_name = f"node-collector-{arcade_safe_name}"
    fluentd_syslog_uri = ecr.get_container_uri('arcade/fluentd-kubernetes-syslog')
    logging.info(fluentd_syslog_uri)
    if not fluentd_syslog_uri:
        logging.error('No arcade/fluentd-kubernetes-syslog container in ECR')
        return False

    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return False

    core_v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()
    apps_v1 = client.AppsV1Api()

    serviceaccount_yaml = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluentd
  namespace: kube-system
  labels:
    k8s-app: fluentd-logging
    version: v1
"""
    service_account = yaml.safe_load(serviceaccount_yaml)

    try:
        response = core_v1.create_namespaced_service_account(
            namespace=service_account['metadata']['namespace'],
            body=service_account,
        )
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = core_v1.replace_namespaced_service_account(
                name=service_account['metadata']['name'],
                namespace=service_account['metadata']['namespace'],
                body=service_account,
            )
        elif api_error.status == 401:
            pass
        else:
            raise api_error

    clusterrole_yaml = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fluentd
rules:
- apiGroups:
  - ''
  resources:
  - pods
  - namespaces
  verbs:
  - get
  - list
  - watch
"""
    cluster_role = yaml.safe_load(clusterrole_yaml)

    try:
        response = rbac_v1.create_cluster_role(
            body=cluster_role,
        )
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = rbac_v1.replace_cluster_role(
                name=cluster_role['metadata']['name'],
                body=cluster_role,
            )
        elif api_error.status == 401:
            pass
        else:
            raise api_error

    clusterrolebinding_yaml = """
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: fluentd
roleRef:
  kind: ClusterRole
  name: fluentd
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: fluentd
  namespace: kube-system
"""
    cluster_role_binding = yaml.safe_load(clusterrolebinding_yaml)

    try:
        response = rbac_v1.create_cluster_role_binding(
            body=cluster_role_binding,
        )
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = rbac_v1.replace_cluster_role_binding(
                name=cluster_role_binding['metadata']['name'],
                body=cluster_role_binding,
            )
        elif api_error.status == 401:
            pass
        else:
            raise api_error

    daemonset_yaml = f"""
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {daemonset_name}
  namespace: kube-system
  labels:
    k8s-app: fluentd-logging
    version: v1
spec:
  selector:
    matchLabels:
      k8s-app: fluentd-logging
  template:
    metadata:
      labels:
        k8s-app: fluentd-logging
        version: v1
    spec:
      serviceAccount: fluentd
      serviceAccountName: fluentd
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: {daemonset_name}
        image: {fluentd_syslog_uri}
        env:
          - name:  SYSLOG_HOST
            value: '{asg_name}'
          - name:  SYSLOG_PORT
            value: '514'
          - name:  SYSLOG_PROTOCOL
            value: 'udp'
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: dockercontainerlogdirectory
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: dockerpodlogdirectory
          mountPath: /var/log/pods
          readOnly: true
      terminationGracePeriodSeconds: 30
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: dockercontainerlogdirectory
        hostPath:
          path: /var/lib/docker/containers
      - name: dockerpodlogdirectory
        hostPath:
          path: /var/log/pods
"""
    daemon_set = yaml.safe_load(daemonset_yaml)

    try:
        response = apps_v1.create_namespaced_daemon_set(
            namespace=daemon_set['metadata']['namespace'],
            body=daemon_set,
        )
    except ApiException as api_error:
        if api_error.status == 409:
            api_response = apps_v1.replace_namespaced_daemon_set(
                namespace=daemon_set['metadata']['namespace'],
                name=daemon_set['metadata']['name'],
                body=daemon_set,
            )
        elif api_error.status == 401:
            pass
        else:
            raise api_error

    return True


# --------------------------------------------------------------------
#
# delete_asteroids_fluentd_daemonset
#
# --------------------------------------------------------------------
def delete_asteroids_fluentd_daemonset(arcade_name: str,
                                      cluster_prefix: str) -> bool:
    """
    Delete ServiceAccount, ClusterRole, ClusterRoleBinding, and DaemonSet for
    fluentd node logging to log-relay.

    Args:
        arcade_name: arcade_name name
        cluster_prefix: the prefix of the log-relay cluster

    Returns:
        bool
    """
    if not cluster_prefix or not arcade_name:
        return False

    arcade_domain = arcade_name.replace('_', '-')
    arcade_safe_name = arcade_name.replace('_', '').replace('.', '-')
    asg_name = f"{cluster_prefix}.{arcade_domain}"
    daemonset_name = f"node-collector-{arcade_safe_name}"
    fluentd_syslog_uri = ecr.get_container_uri('arcade/fluentd-kubernetes-syslog')
    if not fluentd_syslog_uri:
        logging.error('No arcade/fluentd-kubernetes-syslog container in ECR')
        return False

    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return True

    core_v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()
    apps_v1 = client.AppsV1Api()

    daemonset_yaml = f"""
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {daemonset_name}
  namespace: kube-system
  labels:
    k8s-app: fluentd-logging
    version: v1
spec:
  selector:
    matchLabels:
      k8s-app: fluentd-logging
  template:
    metadata:
      labels:
        k8s-app: fluentd-logging
        version: v1
    spec:
      serviceAccount: fluentd
      serviceAccountName: fluentd
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: {daemonset_name}
        image: {fluentd_syslog_uri}
        env:
          - name:  SYSLOG_HOST
            value: '{asg_name}'
          - name:  SYSLOG_PORT
            value: '514'
          - name:  SYSLOG_PROTOCOL
            value: 'udp'
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: dockercontainerlogdirectory
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: dockerpodlogdirectory
          mountPath: /var/log/pods
          readOnly: true
      terminationGracePeriodSeconds: 30
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: dockercontainerlogdirectory
        hostPath:
          path: /var/lib/docker/containers
      - name: dockerpodlogdirectory
        hostPath:
          path: /var/log/pods
"""
    daemon_set = yaml.safe_load(daemonset_yaml)

    try:
        response = apps_v1.delete_namespaced_daemon_set(
            name=daemon_set['metadata']['name'],
            namespace=daemon_set['metadata']['namespace'],
        )
    except ApiException as api_error:
        if api_error.status == 404:
            pass

    serviceaccount_yaml = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluentd
  namespace: kube-system
  labels:
    k8s-app: fluentd-logging
    version: v1
"""
    service_account = yaml.safe_load(serviceaccount_yaml)

    try:
        response = core_v1.delete_namespaced_service_account(
            name=service_account['metadata']['name'],
            namespace=service_account['metadata']['namespace'],
        )
    except ApiException as api_error:
        if api_error.status == 404:
            pass

    clusterrole_yaml = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fluentd
rules:
- apiGroups:
  - ''
  resources:
  - pods
  - namespaces
  verbs:
  - get
  - list
  - watch
"""
    cluster_role = yaml.safe_load(clusterrole_yaml)

    try:
        response = rbac_v1.delete_cluster_role(
            name=cluster_role['metadata']['name'],
        )
    except ApiException as api_error:
        if api_error.status == 404:
            pass

    clusterrolebinding_yaml = """
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: fluentd
roleRef:
  kind: ClusterRole
  name: fluentd
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: fluentd
  namespace: kube-system
"""
    cluster_role_binding = yaml.safe_load(clusterrolebinding_yaml)

    try:
        response = rbac_v1.delete_cluster_role_binding(
            name=cluster_role_binding['metadata']['name'],
        )
    except ApiException as api_error:
        if api_error.status == 404:
            pass

    return False


# --------------------------------------------------------------------
#
# get_asteroids_fluentd_daemonset_info
#
# --------------------------------------------------------------------
def get_asteroids_fluentd_daemonset_info(arcade_name: str,
                                         cluster_prefix: str) -> dict:
    """
    Get DaemonSet info for fluentd node logging to log-relay.

    Args:
        arcade_name: arcade_name name
        cluster_prefix: the prefix of log-relay cluster

    Returns:
        bool
    """
    if not cluster_prefix or not arcade_name:
        return {}

    arcade_domain = arcade_name.replace('_', '-')
    arcade_safe_name = arcade_name.replace('_', '').replace('.', '-')
    asg_name = f"{cluster_prefix}.{arcade_domain}"
    daemonset_name = f"node-collector-{arcade_safe_name}"
    fluentd_syslog_uri = ecr.get_container_uri('arcade/fluentd-kubernetes-syslog')
    if not fluentd_syslog_uri:
        logging.error('No arcade/fluentd-kubernetes-syslog container in ECR')
        return False

    try:
        k8s.load_arcade_k8s_config(arcade_name)
    except ClientError:
        return {}
    apps_v1 = client.AppsV1Api()

    daemonset_yaml = f"""
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {daemonset_name}
  namespace: kube-system
  labels:
    k8s-app: fluentd-logging
    version: v1
spec:
  selector:
    matchLabels:
      k8s-app: fluentd-logging
  template:
    metadata:
      labels:
        k8s-app: fluentd-logging
        version: v1
    spec:
      serviceAccount: fluentd
      serviceAccountName: fluentd
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: {daemonset_name}
        image: {fluentd_syslog_uri}
        env:
          - name:  SYSLOG_HOST
            value: '{asg_name}'
          - name:  SYSLOG_PORT
            value: '514'
          - name:  SYSLOG_PROTOCOL
            value: 'udp'
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: dockercontainerlogdirectory
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: dockerpodlogdirectory
          mountPath: /var/log/pods
          readOnly: true
      terminationGracePeriodSeconds: 30
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: dockercontainerlogdirectory
        hostPath:
          path: /var/lib/docker/containers
      - name: dockerpodlogdirectory
        hostPath:
          path: /var/log/pods
"""
    daemon_set = yaml.safe_load(daemonset_yaml)

    try:
        response = apps_v1.read_namespaced_daemon_set(
            name=daemon_set['metadata']['name'],
            namespace=daemon_set['metadata']['namespace'],
        )
    except ApiException as api_error:
        if api_error.status == 404:
            response = {}

    return response
