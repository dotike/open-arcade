import boto3
import json
import logging
import re


"""
Print statments instead of logging, so we can see whats going on in the logs in Cloudwatch
"""

def update_secret(arcade_name: str,
                  name: str,
                  secret_value: str):
    """
    Update a secret in Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [name of the secret]
        secret_value (str): [vaule of the secret]

    Returns:
        [dict]: [aws api reponse]
    """
    client = boto3.client('secretsmanager')
    kwargs = {"SecretId": f"{arcade_name}/{name}"}

    if isinstance(secret_value, str):
        kwargs["SecretString"] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs["SecretBinary"] = secret_value

    response = client.put_secret_value(**kwargs)

    return {'SecretName': response['Name'], 'SecretARN': response['ARN']}


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
    client = boto3.client("secretsmanager")
    kwargs = {"SecretId": f"{arcade_name}/{name}"}

    if isinstance(secret_value, dict):
        kwargs['SecretString'] = json.dumps(secret_value)

    elif isinstance(secret_value, str):
        kwargs['SecretString'] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs['SecretBinary'] = secret_value

    if versions is not None:
        kwargs['VersionStages'] = versions

    response = client.put_secret_value(**kwargs)

    return response


def create_secret(arcade_name: str, name: str, secret_value, versions=None):
    client = boto3.client('secretsmanager')
    kwargs = {"Name": f"{arcade_name}/{name}"}

    if isinstance(secret_value, dict):
        kwargs['SecretString'] = json.dumps(secret_value)

    elif isinstance(secret_value, str):
        kwargs['SecretString'] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs['SecretBinary'] = secret_value

    if versions is None:
        response = client.create_secret(**kwargs)
        return {'SecretName': response['Name'], 'SecretARN': response['ARN']}
    else:
        response = client.create_secret(**kwargs)
        add_version = update_secret_version(
            arcade_name=arcade_name,
            name=name,
            secret_value=secret_value,
            versions=[versions])
        return {'SecretName': add_version['Name'], 'SecretARN': add_version['ARN']}
    
    
def lambda_handler(event, context):
    collected_secrets = []
    client = boto3.client('sts')
    
    #GET VARS
    account_number = event['account_number']
    role = event['role']
    prefix = event['prefix']
    arcade_name = event['arcade_name']
    
    
    assumed_role_object = client.assume_role(
        RoleArn=f"arn:aws:iam::{account_number}:role/{role}",
        RoleSessionName='AssumeRoleSession')
    
    credentials = assumed_role_object['Credentials']
    
    client = boto3.client('secretsmanager',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          )
    
    paginator = client.get_paginator('list_secrets')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for name in page['SecretList']:
            x = re.search(prefix, name['Name'])
            try:
                collected_secrets.append(x.string)
            except:
                pass
    # Formated list of dictonaries, with the SecretName and Values
    secrets_dict_list = []
    
    for secret in collected_secrets:
        get_secret_value_response = client.get_secret_value(SecretId=secret)
        insert_content = {'SecretName': get_secret_value_response['Name'].split('/')[1], 'Content': json.loads(get_secret_value_response['SecretString'])}
        secrets_dict_list.append(insert_content)
        
    for val in secrets_dict_list:
        try:
            upload_to_child_sm = create_secret(arcade_name=arcade_name, name=val['SecretName'], secret_value=val['Content'])
            print(upload_to_child_sm)

        except client.exceptions.ResourceExistsException as e:
            print(e)
            update = update_secret(arcade_name=arcade_name, name=val['SecretName'], secret_value=json.dumps(val['Content']))
            print(update)

        except client.exceptions.ClientError as e:
            print(e)
            return False

    return True
    
