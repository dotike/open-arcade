# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
parameter_store -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import boto3
import logging

from botocore.exceptions import ClientError


# --------------------------------------------------------------------
#
# put_parameter 
#
# --------------------------------------------------------------------
def put_parameter(arcade_name: str,
                  parameter_name: str,
                  parameter_value: str,
                  data_type: str) -> dict:
    """
    This puts a parameter in aws parameter store

    Args:
        arcade_name (str): [Name of the Arcade]
        parameter_name (str): [Name of the Parameter ex: path/to/somewhere]
        parameter_value (str): [Value of the Parameter]
        data_type (str): 'String'|'SecureString

    Returns:
        [Dict]: [AWS Responses]
    """
    client = boto3.client('ssm')
    response = client.put_parameter(
        Name=f'/{arcade_name}/{parameter_name}',
        Description=f'{arcade_name} {parameter_name} parameters',
        Value=parameter_value,
        Type=data_type,

    )

    return response


# --------------------------------------------------------------------
#
# delete_parameter
#
# --------------------------------------------------------------------
def delete_parameter(arcade_name: str,
                     parameter_name: str) -> dict:
    """
    Deletes a parameter in aws parameter store

    Args:
        arcade_name (str): [Name of the Arcade]
        parameter_name (str): [Name of the Parameter ex: path/to/somewhere]

    Returns:
        [Dict]: [AWS Responses]
    """
    client = boto3.client('ssm')
    response = client.delete_parameter(Name=f'/{arcade_name}/{parameter_name}')

    return response
    

# --------------------------------------------------------------------
#
# get_parameter
#
# --------------------------------------------------------------------
def get_parameter(arcade_name: str,
                  parameter_name: str,
                  decryption=False) -> dict:
    """
    Gets parameter from AWS parameter store

    Args:
        arcade_name (str): [Name of the Arcade]
        parameter_name (str): [Name of the Parameter ex: path/to/somewhere]
        decryption (bool, optional): [description]. Defaults to False.

    Returns:
        [Dict]: [AWS Responses]
    """
    client = boto3.client('ssm')
    response = client.get_parameter(Name=f'/{arcade_name}/{parameter_name}', WithDecryption=decryption)

    return response['Parameter']
