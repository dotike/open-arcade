# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
log_relay -- ARCADE log relay write functions
"""

# @depends: python (>=3.7)
__version__ = '0.1.5'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""

import base64
import logging
import time

import boto3
from botocore.exceptions import ClientError

from arclib import alb
from arclib import asg
from arclib import common
from arclib import eks
from arclib import grv

ASSUME_EC2_ROLE_POLICY_DOCUMENT = {
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

CLOUDWATCH_PUT_RETENTION_POLICY = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "logs:PutRetentionPolicy",
      "Resource": "*"
    }
  ]
}


def delete_asg_configuration(arcade_name: str,
                             cluster_prefix: str) -> bool:
    """

    """
    asg_client = boto3.client('autoscaling')
    lc_name = f"{cluster_prefix}_lc.{arcade_name}"
    asg_sg_name = f"{cluster_prefix}_asg.{arcade_name}"
    if asg.get_asg_configuration_info(lc_name):
        delete_status = asg_client.delete_launch_configuration(LaunchConfigurationName=lc_name)
        if not delete_status['ResponseMetadata']['HTTPStatusCode'] == 200:
            return False
        grv.delete_grv_sg(sg_name=asg_sg_name)
    return True


def create_asg_template(arcade_name: str,
                        cluster_name: str,
                        image_id: str,
                        user_data: str,
                        instance_type: str,
                        block_device_mappings: list) -> bool:
    """

    """
    ec2_client = boto3.client('ec2')
    lt_name = f"{cluster_name}_lt.{arcade_name}"
    asg_sg_name = f"{cluster_name}_asg.{arcade_name}"
    b64_user_data = base64.b64encode(user_data.encode('ascii')).decode('ascii')
    vpc_id = grv.get_vpc_id(arcade_name)
    asg_sg_id = grv.check_if_sg(asg_sg_name)
    if not asg_sg_id:
        asg_sg_id = grv.create_grv_sg(sg_name=asg_sg_name, vpc_id=vpc_id)

    cw_put_policy_name = 'CloudWatchAgentPutLogsRetention'
    cw_put_policy_arn = grv.get_policy_arn(cw_put_policy_name)
    if not cw_put_policy_arn:
        cw_put_policy_arn = grv.create_policy(cw_put_policy_name,
                                              CLOUDWATCH_PUT_RETENTION_POLICY)
    logging.debug(cw_put_policy_arn)

    asg_lrl_profile = "ARCADELogRelayInstanceProfile"
    asg_lrl_policy_arns = ['arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore',
                           'arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy',
                           cw_put_policy_arn]

    profile_status = grv.find_instance_profile(asg_lrl_profile)

    if not profile_status:
        grv.create_instance_profile(role_name=asg_lrl_profile,
            policy_arns=asg_lrl_policy_arns,
            assume_policy=ASSUME_EC2_ROLE_POLICY_DOCUMENT)
        # give create_instance_profile some time to "complete"
        time.sleep(10)

    logging.debug(grv.find_instance_profile(asg_lrl_profile))


    try:
        asg_lt_response = ec2_client.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={
                'IamInstanceProfile': {'Name': asg_lrl_profile},
                'ImageId': image_id,
                'InstanceType': instance_type,
                'KeyName': f"bootstrap.{arcade_name}",  # GSD?
                'SecurityGroupIds': [asg_sg_id],  # Generated
                'UserData': b64_user_data,  # {S3}/externaldata/{gsdname}/filename.ext
                'Monitoring': {'Enabled': False},  # Default
                'EbsOptimized': False,  # GSD
                # AssociatePublicIpAddress=False,
                'BlockDeviceMappings': block_device_mappings,  # GSD
                'TagSpecifications': [
                    {
                        'ResourceType': 'instance',
                        'Tags': [
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
                    },
                ],
            }
        )
    except ec2_client.InvalidLaunchTemplateName.AlreadyExistsException:
        return True

    if asg_lt_response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    return False


def delete_asg_template(arcade_name: str,
                        cluster_prefix: str) -> bool:
    """

    """
    ec2_client = boto3.client('ec2')
    lt_name = f"{cluster_prefix}_lt.{arcade_name}"
    asg_sg_name = f"{cluster_prefix}_asg.{arcade_name}"
    if asg.get_asg_template_info(lt_name):
        delete_status = ec2_client.delete_launch_template(LaunchTemplateName=lt_name)
        if not delete_status['ResponseMetadata']['HTTPStatusCode'] == 200:
            return False
        grv.delete_grv_sg(sg_name=asg_sg_name)
    return True


def create_asg(arcade_name: str, cluster_prefix: str, nodes: int, max_nodes: int) -> str:
    """

    """
    asg_client = boto3.client('autoscaling')
    arcade_domain = arcade_name.replace('_', '-')
    asg_name = f"{cluster_prefix}.{arcade_domain}"
    lc_name = f"{cluster_prefix}_lc.{arcade_name}"
    lt_name = f"{cluster_prefix}_lt.{arcade_name}"
    core_subnets = grv.find_grv_subnets(arcade_name, "core")
    logging.info(core_subnets)

    try:
        asg_response = asg_client.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,  # Generated
            # LaunchConfigurationName=lc_name,  # Generated
            LaunchTemplate={'LaunchTemplateName': lt_name},  # Generated
            MinSize=nodes,  # GSD
            DesiredCapacity=nodes,  # GSD
            MaxSize=max_nodes,  # GSD
            # DefaultCooldown=120,  # default
            # HealthCheckType='EC2',  # default
            # HealthCheckGracePeriod=60,  # default
            # Tags=globalVars['tags'],  # GSD? and generated
            VPCZoneIdentifier=','.join(core_subnets),  # generated
            Tags=[
                    {
                        'ResourceId': asg_name,
                        'ResourceType': 'auto-scaling-group',
                        'Key': 'arcade_tool_provisioned',
                        'Value': common.get_account_id(),
                        'PropagateAtLaunch': True
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
        )
    except asg_client.exceptions.AlreadyExistsFault:
        health = asg.asg_health(asg_name)
        return health

    health = asg.asg_health(asg_name)
    while health != 'HEALTHY':
        time.sleep(30)
        health = asg.asg_health(asg_name)
    return health


def delete_asg(arcade_name: str,
               cluster_prefix: str) -> bool:
    """

    """
    asg_client = boto3.client('autoscaling')
    arcade_domain = arcade_name.replace('_', '-')
    asg_name = f"{cluster_prefix}.{arcade_domain}"
    try:
        response = asg_client.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            ForceDelete=True
        )
    except ClientError:
        return False

    while asg.asg_health(asg_name):
        time.sleep(20)

    return True


# --------------------------------------------------------------------
#
# update_asg
#
# --------------------------------------------------------------------
def maybe_update_asg(arcade_name: str,
               cluster_prefix: str,
               nodegroup_name: str,
               nodegroup_data: dict) -> dict:
    """
    Update an ASG.

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
# create_galaga_nlb
#
# --------------------------------------------------------------------
def create_galaga_nlb(arcade_name: str,
                      cluster_prefix: str,
                      public: bool) -> dict:
    """
    Create an Network Load Balancer.

    Args:
        arcade_name: arcade name
        cluster_prefix: the cluster prefix to associate this nlb with.
        public: is this a public or internal nlb

    Returns:
        dict of nlb status response or exception dict
    """
    elb_client = boto3.client('elbv2')
    nlb_dict = alb.get_nlb_dict(arcade_name, public)
    nlb_name = f"{cluster_prefix}-{nlb_dict['name']}"

    subnets = grv.find_grv_subnets(arcade_name, nlb_dict['subnet_name'])

    if not subnets:
        return {'Code': 'failed',
                'Reason': f"{nlb_dict['subnet_name']} subnets do not exists for {arcade_name}"}

    response = elb_client.create_load_balancer(
        Name=nlb_name,
        Subnets=subnets,
        Scheme=nlb_dict['scheme'],
        Tags=[
            {
                'Key': 'Name',
                'Value': nlb_name,
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
                'Key': 'arcade_name',
                'Value': arcade_name,
            }
        ],
        Type='network',
    )

    nlb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    status = alb.get_alb_status(nlb_name)

    while 'provisioning' == status['State']['Code']:
        print(f"Waiting for the nlb {nlb_name} to be active")
        time.sleep(20)
        status = alb.get_alb_status(nlb_name)

    print(f"{nlb_name} NLB Created with scheme {nlb_dict['scheme']}")

    return status


# --------------------------------------------------------------------
#
# delete_galaga_nlb
#
# --------------------------------------------------------------------
def delete_galaga_nlb(arcade_name: str,
                      cluster_prefix: str,
                      public: bool) -> bool:
    """
    Delete an NLB.

    Args:
        arcade_name: gravitar name to delete NLBs from
        public: is this a public or internal nlb

    Returns:
    True if nlb is deleted or not available, or False
    """
    elb_client = boto3.client('elbv2')

    nlb_dict = alb.get_nlb_dict(arcade_name, public)
    nlb_name = f"{cluster_prefix}-{nlb_dict['name']}"

    nlb_arn = alb.find_alb_arn(nlb_name)

    if not nlb_arn:
        return True

    response = elb_client.delete_load_balancer(LoadBalancerArn=nlb_arn)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return False

    print(f"Deleted nlb {nlb_dict['name']}")

    return True


# --------------------------------------------------------------------
#
# create_galaga_nlb_listener
#
# --------------------------------------------------------------------
def create_galaga_nlb_listener(arcade_name: str,
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
    nlb_name = f"{name}-{prefix}nlb-{arcade_name.replace('_', '').replace('.', '-')}"
    nlb_arn = alb.find_alb_arn(alb_name=nlb_name)
    asg_tg_name = f"{prefix}-{arcade_name}-{name}-{tg_protocol}-{tg_port}"

    response = elb_client.create_listener(
        LoadBalancerArn=nlb_arn,
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
# delete_galaga_nlb_listener
#
# --------------------------------------------------------------------
def delete_galaga_nlb_listener(arcade_name: str,
                               cluster_prefix: str,
                               lb_type: str,
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
    print(target_group_info)
    listener_arn = find_nlb_listener_arn(arcade_name, cluster_prefix, lb_type, target_group_info['Port'])[0]
    print(f"dgnl => {listener_arn}")
    response = elb_client.delete_listener(
        ListenerArn=listener_arn
    )

    return response


# --------------------------------------------------------------------
#
# find_nlb_listener_arn
#
# --------------------------------------------------------------------
def find_nlb_listener_arn(arcade_name:str,
                          cluster_prefix: str,
                          lb_type: str,
                          port=80) -> tuple:
    """Find the Listener ARN of a ALB.

    Args:
        arcade_name (str): [Arcade Name]
        asd_data (dict): [ASD data]

    Returns:
        tuple: [ALB Listener ARN and ALB ARN]
    """
    elb_client = boto3.client('elbv2')

    nlb_name = f"{cluster_prefix}-{lb_type}nlb-{arcade_name.replace('_', '').replace('.', '-')}"
    print(f"fnla => {nlb_name}")
    nlb_arn = alb.find_alb_arn(nlb_name)
    print(f"fnla => {nlb_arn}")

    try:
        response = elb_client.describe_listeners(
            LoadBalancerArn=nlb_arn,
        )
        for listener in response['Listeners']:
            if listener['Port'] == port:
                return (listener['ListenerArn'], listener['LoadBalancerArn'])
    except ClientError as c_e:
        logging.info(c_e)
        return ('', '')


def create_relay_log_group(arcade_name: str) -> bool:
    """Creates a log group in cloudwatch for the log-relay

    Args:
        arcade_name (str): Name of the arcade

    Returns:
        bool: True if log group was created. False if not.
    """
    client = boto3.client('logs')
    arcade_domain = arcade_name.replace('_', '-')
    asg_name = f"log-relay.{arcade_domain}"
    response = client.create_log_group(logGroupName=asg_name)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False
    
    
def set_relay_log_group_retention(arcade_name: str, retention_in_days: int) -> bool:
    """Sets the log retention in cloudwatch

    Args:
        arcade_name (str): Name of the Arcade
        retention_in_days (int): How long we want to retain the logs in cloudwatch

    Returns:
        bool: True if successful, False if not successful.
    """
    client = boto3.client('logs')
    arcade_domain = arcade_name.replace('_', '-')
    asg_name = f"log-relay.{arcade_domain}"
    response = client.put_retention_policy(logGroupName=asg_name, retentionInDays=retention_in_days)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False
    

def delete_relay_log_group(arcade_name: str) -> bool:
    """Deletes a log group from cloudwatch

    Args:
        arcade_name (str): Name of the Arcade

    Returns:
        bool: True if deleted, False if not.
    """
    client = boto3.client('logs')
    arcade_domain = arcade_name.replace('_', '-')
    asg_name = f"log-relay.{arcade_domain}"
    response = client.delete_log_group(logGroupName=asg_name)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False