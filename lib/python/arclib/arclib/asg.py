# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
asg --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import logging
import os
from pprint import pprint
import time
import boto3
from botocore.exceptions import ClientError
from arclib import common, grv


ASSUME_SSM_ROLE_POLICY_DOCUMENT = {
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


def asg_health(asg_name: str) -> str:
    """
    Args:
        asg_name str:
    """
    asg_client = boto3.client('autoscaling')
    response = asg_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )
    try:
        number_healthy = 0
        for node in response['AutoScalingGroups'][0]['Instances']:
            if node['HealthStatus'] == 'Healthy':
                number_healthy += 1
        if number_healthy == response['AutoScalingGroups'][0]['DesiredCapacity']:
            return "HEALTHY"
        return "UNHEALTHY"
    except IndexError:
        return ""


def get_asg_info(asg_name: str) -> dict:
    """
    Args:
        asg_name str:
    """
    asg_client = boto3.client('autoscaling')
    try:
        response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        return response['AutoScalingGroups'][0]
    except (ClientError, IndexError):
        return ""


def get_asg_configuration_info(asg_lc_name: str) -> dict:
    """
    Args:
        asg_lc_name str:
    """
    asg_client = boto3.client('autoscaling')
    try:
        response = asg_client.describe_launch_configurations(LaunchConfigurationNames=[asg_lc_name])
        return response['LaunchConfigurations']
    except ClientError:
        return ""


def get_asg_template_info(asg_lt_name: str) -> dict:
    """
    Args:
        asg_lt_name str:
    """
    ec2_client = boto3.client('ec2')
    try:
        response = ec2_client.describe_launch_templates(LaunchTemplateNames=[asg_lt_name])
        return response['LaunchTemplates']
    except ClientError:
        return ""


def create_asg_configuration(arcade_name: str,
                             cluster_name: str,
                             image_id: str,
                             user_data: str,
                             instance_type: str,
                             block_device_mappings: list) -> bool:
    """

    """
    asg_client = boto3.client('autoscaling')
    lc_name = f"{cluster_name}_lc.{arcade_name}"
    asg_sg_name = f"{cluster_name}_asg.{arcade_name}"
    vpc_id = grv.get_vpc_id(arcade_name)
    asg_sg_id = grv.check_if_sg(asg_sg_name)
    if not asg_sg_id:
        asg_sg_id = grv.create_grv_sg(sg_name=asg_sg_name, vpc_id=vpc_id)

    asg_ssm_profile = "ARCADESSMInstanceProfile"
    asg_ssm_policy_arns = ['arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore']

    profile_status = grv.find_instance_profile(asg_ssm_profile)

    if not profile_status:
        grv.create_instance_profile(role_name=asg_ssm_profile,
            policy_arns=asg_ssm_policy_arns,
            assume_policy=ASSUME_SSM_ROLE_POLICY_DOCUMENT)
        # give create_instance_profile some time to "complete"
        time.sleep(10)

    logging.debug(grv.find_instance_profile(asg_ssm_profile))


    asg_lc_response = asg_client.create_launch_configuration(
        LaunchConfigurationName=lc_name,
        IamInstanceProfile=asg_ssm_profile,
        ImageId=image_id,
        KeyName=f'bootstrap.{arcade_name}',  # GSD?
        SecurityGroups=[asg_sg_id],  # Generated
        UserData=user_data,  # {S3}/externaldata/{gsdname}/filename.ext
        InstanceType=instance_type,
        InstanceMonitoring={'Enabled': False},  # Default
        EbsOptimized=False,  # GSD
        AssociatePublicIpAddress=False,
        BlockDeviceMappings=block_device_mappings  # GSD
    )

    if asg_lc_response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    return False


def delete_asg_configuration(arcade_name: str, cluster_name: str) -> bool:
    """

    """
    asg_client = boto3.client('autoscaling')
    lc_name = f"{cluster_name}_lc.{arcade_name}"
    asg_sg_name = f"{cluster_name}_asg.{arcade_name}"
    delete_status = asg_client.delete_launch_configuration(LaunchConfigurationName=lc_name)
    if delete_status['ResponseMetadata']['HTTPStatusCode'] == 200:
        grv.delete_grv_sg(sg_name=asg_sg_name)
        return True
    return False


def create_asg(arcade_name: str, cluster_name: str, nodes: int, max_nodes: int) -> str:
    """

    """
    asg_client = boto3.client('autoscaling')
    asg_name = f"{cluster_name}-{arcade_name}"
    lc_name = f"{cluster_name}_lc.{arcade_name}"
    asg_sg_name = f"{cluster_name}_asg.{arcade_name}"
    vpc_id = grv.get_vpc_id(arcade_name)
    asg_sg_id = grv.check_if_sg(asg_sg_name)
    core_subnets = grv.find_grv_subnets(arcade_name, "core")
    logging.info(core_subnets)

    asg_response = asg_client.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,  # Generated
        LaunchConfigurationName=lc_name,  # Generated
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
            ],
    )

    health = asg_health(asg_name)
    while health != 'HEALTHY':
        time.sleep(30)
        health = asg_health(asg_name)
    return health


def delete_asg(arcade_name: str, cluster_name: str) -> bool:
    """

    """
    asg_client = boto3.client('autoscaling')
    asg_name = f"{cluster_name}-{arcade_name}"
    try:
        response = asg_client.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            ForceDelete=True
        )
    except ClientError:
        return False

    while asg_health(asg_name):
        time.sleep(20)

    return True


def import_galaga_dict() -> dict:
    galaga_dict = {}
    for key, value in os.environ.items():
        if 'GALAGA_' in key:
            galaga_key = key.replace('GALAGA_', '').lower()
            galaga_dict[galaga_key] = value
    return galaga_dict
