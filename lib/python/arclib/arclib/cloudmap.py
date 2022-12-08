# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
cloudmap -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import boto3

# --------------------------------------------------------------------
#
# get_cloudmap_status 
#
# --------------------------------------------------------------------
def get_cloudmap_status(arcade_name: str) -> dict:
    """
    Return the status of cloud map namespace.

    Args:
        arcade_name: the name of arcade
        
    Returns:
        status dict of the cloud map namespace or empty dict
    """
    client = boto3.client('servicediscovery')
    cloudmap_namespace = f'arcade.{arcade_name}'

    namespace_filter = [{'Name': 'TYPE', 'Values': ['DNS_PRIVATE'], 'Condition': 'EQ'}]

    response = client.list_namespaces(Filters=namespace_filter)

    for namespace in response['Namespaces']:
        if namespace['Name'] == cloudmap_namespace:
            return namespace
        
    return {}


# --------------------------------------------------------------------
#
# create_cloudmap_namespace 
#
# --------------------------------------------------------------------
def create_cloudmap_namespace(vpc_id: str,
                              arcade_name: str) -> dict:
    """
    Create cloud map namespace.

    Args:
        vpc_id: the vpc id of the arcade
        arcade_name: the name of arcade
        
    Returns:
        the ResponseMetadata of creating cloud map namespace or empty dict
    """
    client = boto3.client('servicediscovery')
    cloudmap_namespace = f'arcade.{arcade_name}'
    response = client.create_private_dns_namespace(Name=cloudmap_namespace, Vpc=vpc_id)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return response['ResponseMetadata']
    
    return {}


# --------------------------------------------------------------------
#
# delete_cloudmap_namespace
#
# --------------------------------------------------------------------
def delete_cloudmap_namespace(arcade_name: str) -> dict:
    """
    Delete cloud map namespace.

    Args:
        arcade_name: the name of arcade
        
    Returns:
        empty dict of the exception response dict
    """
    client = boto3.client('servicediscovery')
    response = get_cloudmap_status(arcade_name)

    if response:
        try:
            client.delete_namespace(Id=response['Id'])
            return {}
        except client.exceptions.ResourceInUse as e:
            return e.response

    return {}
