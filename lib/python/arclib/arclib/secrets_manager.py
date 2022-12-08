# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
alb -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import boto3
import json
import logging
import re
import os
import secrets
import uuid

from botocore.exceptions import ClientError
from arclib import storage, grv

# --------------------------------------------------------------------
#
# delete_event
#
# --------------------------------------------------------------------
def delete_event(arcade_name: str, event_name: str) -> bool:
    """Deletes a event from Amazon Event Bridge

    Args:
        arcade_name (str): [Arcade Name]
        event_name (str): [Name of the event]

    Returns:
        bool: [True if event is removed, False if event is not removed]
    """
    client = boto3.client('events') 
    response = client.delete_rule(Name=f"{arcade_name.split('.')[0]}-{event_name}", Force=True)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

# --------------------------------------------------------------------
#
# delete_lambda
#
# --------------------------------------------------------------------
def delete_lambda(arcade_name: str, function_name) -> bool:
    """Deletes a Lambda Function

    Args:
        arcade_name (str): [arcade name]
        function_name ([type]): [lambda function name]

    Returns:
        bool: [True if the function is removed False if not]
    """
    client = boto3.client('lambda')
    response = client.delete_function(FunctionName=f"{arcade_name.split('.')[0]}-{function_name}")
    if response['ResponseMetadata']['HTTPStatusCode'] == 200 or 204:
        return True
    else:
        return False

    
    
# --------------------------------------------------------------------
#
# find_lambda
#
# --------------------------------------------------------------------
def find_lambda(arcade_name: str, function_name: str) -> bool:
    """Finds lambda in aws account

    Args:
        arcade_name (str): [arcade name]
        function_name (str): [lambda function name]

    Returns:
        bool: [True if the function is present False if not]
    """
    client = boto3.client('lambda')
    response = client.get_function(FunctionName=f"{arcade_name.split('.')[0]}-{function_name}")
    if response['Configuration']['FunctionName'] == f"{arcade_name.split('.')[0]}-{function_name}":
        return True
    else:
        return False


# --------------------------------------------------------------------
#
# create_secrets_manager_policies
#
# --------------------------------------------------------------------
def create_secrets_manager_policies(super_service_account: str, super_service_role_name: str):
    """Creates polices for Cross Account Sync for Secrets Manager

    Args:
        super_service_account (str): [super service account number]
        super_service_role_name (str): [super service role name]

    Returns:
        [type]: [description]
    """
    client = boto3.client('iam')
    arn_list = []
    get_account_num = boto3.client('sts').get_caller_identity().get('Account')
    secrets_manger_assume_role = {
         "Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "sts:AssumeRole",
             "Resource": f"arn:aws:iam::{super_service_account}:role/{super_service_role_name}"
         }
         
    }
    
    secrets_manger_policy_2 = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "secretsmanager:ListSecrets",
            "Resource": "*"
        }
    }
    
    log_policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    }
    
    secrets_manager_policy = {
        "Version": "2012-10-17",
        "Statement": 
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:CreateSecret",
                    "secretsmanager:DeleteSecret",
                    "secretsmanager:ListSecretVersionIds",
                    "secretsmanager:UpdateSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:StopReplicationToReplica",
                    "secretsmanager:ReplicateSecretToRegions",
                    "secretsmanager:RestoreSecret",
                    "secretsmanager:RotateSecret",
                    "secretsmanager:UpdateSecretVersionStage",
                    "secretsmanager:RemoveRegionsFromReplication"
                ],
                "Resource": f"arn:aws:secretsmanager:*:{get_account_num}:secret:*"
            }
    }
    
    try:
        log_p = client.create_policy(
            PolicyName='LogLambda',
            PolicyDocument=json.dumps(log_policy)
        )
        arn_list.append(log_p['Policy']['Arn'])
    except:
        arn = f"arn:aws:iam::{get_account_num}:policy/LogLambda"
        arn_list.append(arn)
    
    try:
        policy_secrets_manager_policy = client.create_policy(
            PolicyName='SecretsManagerSyncPolicy',
            PolicyDocument=json.dumps(secrets_manager_policy)
        )
        arn_list.append(policy_secrets_manager_policy['Policy']['Arn'])
    except:
        # Get ARN
        arn = f"arn:aws:iam::{get_account_num}:policy/SecretsManagerSyncPolicy"
        arn_list.append(arn)
    
    try:
        policy_secrets_manger_assume_role = client.create_policy(
            PolicyName='SecretsManagerSyncPolicyAssumeRole', 
            PolicyDocument=json.dumps(secrets_manger_assume_role))
        arn_list.append(policy_secrets_manger_assume_role['Policy']['Arn'])
    except:
        arn = f"arn:aws:iam::{get_account_num}:policy/SecretsManagerSyncPolicyAssumeRole"
        arn_list.append(arn)
    
    try:
        policy_secrets_manager_policy2 = client.create_policy(
            PolicyName='SecretsManagerSyncPolicy2', 
            PolicyDocument=json.dumps(secrets_manger_policy_2))
        arn_list.append(policy_secrets_manager_policy2['Policy']['Arn'])
    except:
        arn = f"arn:aws:iam::{get_account_num}:policy/SecretsManagerSyncPolicy2"
        arn_list.append(arn)

    return arn_list


# --------------------------------------------------------------------
#
# lambda_roles_sync
#
# --------------------------------------------------------------------
def lambda_roles_sync(super_service_account: str, super_service_role_name: str):
    """Creates permissions for the sync in cross accounts
       Creates Role for Lambda Cross account Secrets Manager sync
    """
    client = boto3.client('iam')
    
    # Get_Policy
    policy_list = create_secrets_manager_policies(super_service_account, super_service_role_name)
    
    d = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole"
                ],
                "Principal": {
                    "Service": [
                        "lambda.amazonaws.com"
                    ]
                }
            }
        ]
    }
    try:
        response = client.create_role(
            RoleName='LambdaSSRoleExecution',
            AssumeRolePolicyDocument=json.dumps(d))
    except:
        response = False
    
    try:
        for policy in policy_list:
            client.attach_role_policy(
                RoleName='LambdaSSRoleExecution',
                PolicyArn=policy
            )
    except:
        pass
        
    if response:
        return True
    else:
        return False


# --------------------------------------------------------------------
#
# upload_lambda
#
# --------------------------------------------------------------------
def upload_lambda(session: boto3.session.Session, arcade_name: str, name: str, path: str, s3_path: str):
    """[summary]

    Args:
        session (boto3.session.Session): [description]
        arcade_name (str): [arcade name]
        name (str): [description]
        path (str): [description]
        s3_path (str): [path in s3]

    Returns:
        [type]: [description]
    """
    s3_client = session.client('s3')
    app_bucket = storage.get_arcade_buckets(session, arcade_name)['infrastructure']
    for root, dirs, files in os.walk(path):
        if name in files:
            zipfile = os.path.join(root, name)
            try:
                response = s3_client.upload_file(
                    zipfile, app_bucket, s3_path
                )
            except ClientError as e:
                return False
            return True


# --------------------------------------------------------------------
#
# find_lambda_arn
#
# --------------------------------------------------------------------
def find_lambda_arn(lambda_name: str) -> str:
    """Finds a lambda arn 

    Args:
        lambda_name (str): [name of lambda function]

    Returns:
        str: [description]
    """
    client = boto3.client('lambda')
    response = client.get_function(
        FunctionName = lambda_name
    )
    return response['Configuration']['FunctionArn']


# --------------------------------------------------------------------
#
# add_source_event_to_lambda
#
# --------------------------------------------------------------------
def add_source_event_to_lambda(arcade_name: str, function_name: str, action: str, principal: str, source_arn: str) -> bool:
    """Adds a source event to lambda

    Args:
        arcade_name (str): [arcade name]
        function_name (str): [name of lambda function]
        action (str): [ex lambda:InvokeFunction]
        principal (str): [ex events.amazonaws.com]
        source_arn (str): [source of the event in event bridge]

    Returns:
        bool: [description]
    """
    client = boto3.client('lambda')
    response = client.add_permission(
        FunctionName = f"{arcade_name.split('.')[0]}-{function_name}",
        StatementId = str(uuid.uuid4()),
        Action = action,
        Principal = principal,
        SourceArn = source_arn
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


# --------------------------------------------------------------------
#
# create_lambda_event
#
# --------------------------------------------------------------------
def create_lambda_event(event_name: str, arcade_name: str, rate: str, target_arn: str, event_input: str):
    """[summary]

    Args:
        event_name (str): [Event Name]
        arcade_name (str): [Arcade name]
        rate (str): [rate(2 minutes) or Cron style]
        target_arn (str): [Lambda ARN]
        event_input (str): [JSON string for event]

    Returns:
        [type]: bool
    """
    client = boto3.client('events')
    rule = client.put_rule(
        Name = f"{arcade_name.split('.')[0]}-{event_name}",
        ScheduleExpression = rate,
        State = "ENABLED")
    if rule['ResponseMetadata']['HTTPStatusCode'] == 200:
        add_target = client.put_targets(
            Rule = f"{arcade_name.split('.')[0]}-{event_name}",
            Targets = [
                {
                    'Arn': target_arn,
                    'Id': str(uuid.uuid4()),
                    'Input': str(event_input)
                }
            ]
        )
        if add_target['ResponseMetadata']['HTTPStatusCode'] == 200:
            return (True, rule['RuleArn'])
        else:
            return False
    else:
        return False


# --------------------------------------------------------------------
#
# lambda_publish
#
# --------------------------------------------------------------------
def lambda_publish(session: boto3.session.Session(), function_name: str, arcade_name: str, zip_file_name: str, 
                   timeout: int, memorysize: int, runtime: str, role: str, description='') -> bool:
    """Publishes a Lambda to AWS

    Args:
        session (boto3.session.Session): [boto3 session]
        arcade_name (str): [arcade name]
        zip_file_name (str): [name of the zip file in $MYHIER lambda functions dir]
        timeout (int): [Lambda Timeout, refer to AWS documentation]
        memorysize (int): [Lambda Memory Size, refer to AWS documentation]
        runtime (str): [Lambda Code Runtime, refer to AWS documentation]
        description (str): [Optional]

    Returns:
        [Bool: [True if lambda was created False if not]
    """
    account_number = boto3.client('sts').get_caller_identity().get('Account')
    app_bucket = storage.get_arcade_buckets(session, arcade_name)['infrastructure']
    lambda_client = session.client('lambda')
    lambda_functions_path = f"{os.environ['MYHIER']}/libexec/lambda_functions"
    push_lambda = upload_lambda(session, arcade_name, zip_file_name, lambda_functions_path, f'lambda/{zip_file_name}')
    logging.info(push_lambda)
    response = lambda_client.create_function(
        FunctionName = f"{arcade_name.split('.')[0]}-{function_name}",
        Runtime = runtime,
        Role = role,
        Handler = 'secrets_manager_sync.lambda_handler',
        Description=description,
        Code = {
          'S3Bucket': app_bucket,
          'S3Key': f'lambda/{zip_file_name}'
        },
        Timeout = timeout,
        MemorySize = memorysize,
        PackageType = 'Zip',
        Publish = True,
    )
    logging.info(response)
    if response['ResponseMetadata']['HTTPStatusCode'] == 201 or 200:
        return True
    else:
        return False


# --------------------------------------------------------------------
#
# find_secrets_to_delete
#
# --------------------------------------------------------------------
def find_secrets_to_delete(arcade_name: str) -> list:
    """
    [summary]

    Args:
        arcade_name (str): [name of the arcade]

    Returns:
        list: [List of secrets for a arcade]
    """
    collected_secrets = []
    client = boto3.client('secretsmanager')
    paginator = client.get_paginator('list_secrets')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for name in page['SecretList']:
            x = re.search(arcade_name, name['Name'])
            try:
                collected_secrets.append(x.string)
            except:
                pass
    # TODO: Temporary Remove rds_default_credentials until we orginize the RDS default Creds

    if f'{arcade_name}/rds_default_credentials' in collected_secrets:
        collected_secrets.remove(f'{arcade_name}/rds_default_credentials')

    return collected_secrets


# --------------------------------------------------------------------
#
# rds_default_creds
#
# --------------------------------------------------------------------
def rds_default_creds(arcade_name: str,
                      name='rds_default_credentials', length=12):
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
    try:
        create_p = secrets.token_urlsafe(length)
        s_value = {
            'username': f'{arcade_trim}_admin',
            'password': create_p
        }

        create_rds_cred = create_secret(
            arcade_name=arcade_name,
            name=name,
            secret_value=s_value
        )
        return True
    except ClientError as e:
        print(e)
        logging.info(e)
        return False


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


# --------------------------------------------------------------------
#
# create_secret
#
# --------------------------------------------------------------------
def create_secret(name: str,
                  secret_value,
                  versions=None, arcade_name=None):
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
    client = boto3.client('secretsmanager')
    if arcade_name == None:
        kwargs = {"Name": f"{name}"}
    else:
        kwargs = {"Name": f"{arcade_name}/{name}"}

    if isinstance(secret_value, dict):
        kwargs['SecretString'] = json.dumps(secret_value)

    elif isinstance(secret_value, str):
        kwargs['SecretString'] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs['SecretBinary'] = secret_value

    if versions is None:
        response = client.create_secret(**kwargs)
        logging.info(response)
        return {'SecretName': response['Name'], 'SecretARN': response['ARN']}
    else:
        response = client.create_secret(**kwargs)
        logging.info(response)
        add_version = update_secret_version(
            arcade_name=arcade_name,
            name=name,
            secret_value=secret_value,
            versions=[versions])
        return {'SecretName': add_version['Name'], 'SecretARN': add_version['ARN']}


# --------------------------------------------------------------------
#
# delete_secret
#
# --------------------------------------------------------------------
def delete_secret(arcade_name: str,
                  name: str,
                  without_recovery=False):
    """
    Deletes Secret from Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [Name of the Secret]
        without_recovery (bool, optional): [Delete with no Recovery]. Defaults to False.

    Returns:
        [dict]: [aws api return]
    """
    client = boto3.client('secretsmanager')
    secret_full_path = f"{arcade_name}/{name}"
    response = client.delete_secret(SecretId=secret_full_path, ForceDeleteWithoutRecovery=without_recovery)
    logging.info(response)
    return response


# --------------------------------------------------------------------
#
# list_sevrets
#
# --------------------------------------------------------------------
def list_secrets(arcade_name: str):
    """
    Args:

    Returns:

    """
    list_of_sec = []
    client = boto3.client('secretsmanager')
    paginator = client.get_paginator('list_secrets')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for x in page['SecretList']:
            list_of_sec.append(x['Name'])
    r = re.compile(f"{arcade_name}/*")
    found_sec = list(filter(r.match, list_of_sec))
    return found_sec


# --------------------------------------------------------------------
#
# get_secret
#
# --------------------------------------------------------------------
def get_secret(name: str,
               version=None, arcade_name=None):
    """
    Gets A Secret Value from Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [name of the secret]
        version ([type], optional): [version of the secret]. Defaults to None.

    Returns:
        [str]: [value of the secret]
    """
    client = boto3.client('secretsmanager')
    if arcade_name == None:
        kwargs = {"SecretId": f"{name}"}
    else:
        kwargs = {"SecretId": f"{arcade_name}/{name}"}
    if version is not None:
        kwargs['VersionStage'] = version

    response = client.get_secret_value(**kwargs)
    logging.info(response)

    return response['SecretString']

# --------------------------------------------------------------------
#
# update_secret
#
# --------------------------------------------------------------------
def update_secret(name: str,
                  secret_value: str, arcade_name=None):
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
    if arcade_name == None:
        kwargs = {"SecretId": f"{name}"}
    else:
        kwargs = {"SecretId": f"{arcade_name}/{name}"}

    if isinstance(secret_value, str):
        kwargs["SecretString"] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs["SecretBinary"] = secret_value

    response = client.put_secret_value(**kwargs)
    logging.info(response)

    return {'SecretName': response['Name'], 'SecretARN': response['ARN']}


# --------------------------------------------------------------------
#
# SecretsManagerSync
#
# --------------------------------------------------------------------
def SecretsMangerSync(arcade_name: str,
                      account_number: str,
                      role: str,
                      prefix: str) -> bool:
    """
    This function will perform cross acount sync with secretsmanager. It will
    look at a prefix and grab all secrets that have that prefix and upload to
    the child (source) account. If there is a update to a secret from the
    superservice account and this is ran, it will update the secret.

    Args:
        arcade_name (str): [Name of the Arcade]
        account_number (str): [AWS account number]
        role (str): [name of the role the will be assumed]
        prefix (str): [prefix that will handle wildcards ex: superservice/*]

    Returns:
        [bool]: [True == Success, False == Failure]
    """
    collected_secrets = []
    client = boto3.client('sts')

    assumed_role_object = client.assume_role(
        RoleArn=f"arn:aws:iam::{account_number}:role/{role}",
        RoleSessionName='AssumeRoleSession')

    credentials = assumed_role_object['Credentials']

    client = boto3.client('secretsmanager',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          )
    # Get all secrets into a list for sorting

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

    # Now we need to upload to the current child account

    for val in secrets_dict_list:
        try:
            upload_to_child_sm = create_secret(arcade_name=arcade_name, name=val['SecretName'], secret_value=val['Content'])
            logging.info(upload_to_child_sm)

        except client.exceptions.ResourceExistsException as e:
            logging.info(e)
            update = update_secret(arcade_name=arcade_name, name=val['SecretName'], secret_value=json.dumps(val['Content']))
            logging.info(update)

        except client.exceptions.ClientError as e:
            logging.info(e)
            return FalseClientError

    return True


# --------------------------------------------------------------------
#
# 
#
# --------------------------------------------------------------------
def get_secret_arn(name: str) -> str:
    """Retrieve the ARN using a secret's name.

    Args:
        name (str): [Name of the secret]

    Returns:
        [str]: ARN of secret
    """
    client = boto3.client("secretsmanager")
    response = client.describe_secret(SecretId=name)
    return response['ARN']


