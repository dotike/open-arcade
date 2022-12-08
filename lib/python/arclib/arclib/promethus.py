# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
Common Libary for Promtheus/Grafana Functions for other tools to use
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.1'

import boto3
from botocore.exceptions import ClientError
import time
from arclib import common


def get_aws_prometheus_workspace_id(arcade_name: str) -> str:
    """Fetchs Prometheus Workspace Remote Write URL

    Args:
        arcade_name (str): Name of the arcade

    Returns:
        str: returns a string of the prometheus url
    """
    client = boto3.client('arcade')
    region = common.get_arcade_region(arcade_name=arcade_name)
    response = client.list_workspaces(alias=f"prometheus-{arcade_name}")
    url = f"https://aps-workspaces.{region}.amazonaws.com/workspaces/{response['workspaces'][0]['workspaceId']}/api/v1/remote_write"
    return url


def get_grafana_status(arcade_name: str):
    """Gets the status of managed grafana being created

    Args:
        arcade_name (str): Name of the arcade

    Returns:
        str: status of grafana
    """
    client = boto3.client('grafana')
    try:
        get_id = client.list_workspaces()
        workspaces = [x for x in get_id['workspaces'] if x['name'] == f'{arcade_name}-grafana']
        get_workspace_id = workspaces[0]['endpoint'].split('.')[0]
        response = client.describe_workspace(workspaceId=get_workspace_id)
        get_status = response['workspace']['status']
        return get_status
    except ClientError as e:
        return e


def get_grafana_url(arcade_name: str) -> str:
    """Returns the url of the aws managed grafana

    Args:
        arcade_name (str): Name of the Arcade

    Returns:
        str: Returns the URL of Grafana, empty string if no grafana
    """
    status_list = []
    client = boto3.client('grafana')
    list_of_workspaces = []
    response = client.list_workspaces()
    
    for x in response['workspaces']:
        if f'{arcade_name}-grafana' in x['name']:
            list_of_workspaces.append(x)
    
    status = get_grafana_status(arcade_name=arcade_name)
    status_list.insert(0, str(status))
    while status_list[0] == 'CREATING':
        time.sleep(1)
        new_status = get_grafana_status(arcade_name=arcade_name)
        if status_list[0] == 'CREATING':
            status_list.insert(0, str(new_status))
            continue
        if status_list[0] == 'ACTIVE':
            break
    
    if list_of_workspaces == []:
        return ''
    else:
        return list_of_workspaces[0]['endpoint']
    
    
def get_prometheus_grafana_role(arcade_name: str, application: str) -> bool:
    """Verifies that the Prometheus or Grafana Role is present

    Args:
        arcade_name (str): Name of the arcade
        application (str): prometheus or grafana as the application name

    Returns:
        bool: True if the role is present, False if the role is not present
    """
    if application == 'grafana':
        role_name = f'{arcade_name}-graphana-role'
    if application == 'prometheus':
        role_name = f'{arcade_name}-EKS-ARCADE-ServiceAccount-Role' 
    
    client = boto3.client('iam')
    
    try:
        response = client.get_role(RoleName=role_name)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return True
        else:
            return False
    except client.exceptions.NoSuchEntityException:
        return False
    
