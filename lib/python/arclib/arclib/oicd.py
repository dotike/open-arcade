# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
oicd -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


from kubernetes import client, config, common
from kubernetes.client.rest import ApiException
import json
import boto3
import hashlib

# --------------------------------------------------------------------
#
# get_role_for_kube
#
# --------------------------------------------------------------------
def get_role_for_kube(role_name):
    client = boto3.client('iam')
    response = client.get_role(RoleName=role_name)
    return response['Role']['Arn']


# --------------------------------------------------------------------
#
# create_service_account
#
# --------------------------------------------------------------------
def create_service_account(arn_role, arcade):
    x = {"apiVersion":"v1",
         "kind":"ServiceAccount",
         "metadata": 
             {"annotations":
                 {'eks.amazonaws.com/role-arn': arn_role},
                 "name": arcade.split('.')[0].replace('_', '-'),
                 "namespace":"default"}}
    config.load_kube_config()
    coa = client.CoreV1Api()
    a = coa.create_namespaced_service_account(
        namespace='default',
        body=x)
    return a


# --------------------------------------------------------------------
#
# get_oicd_provider
#
# --------------------------------------------------------------------
def get_oidc_provider(cluster):
    client = boto3.client('eks')
    response = client.describe_cluster(name=cluster)
    return response['cluster']['identity']['oidc']['issuer']


# --------------------------------------------------------------------
#
# get_oicd_provider_cert_sha1
#
# --------------------------------------------------------------------
def get_oidc_provider_cert_sha1(cluster):
    client = boto3.client('eks')
    response = client.describe_cluster(name=cluster)
    cert = response['cluster']['certificateAuthority']['data']
    hash_object = hashlib.sha1(cert.encode('utf-8'))
    return hash_object.hexdigest()


# --------------------------------------------------------------------
#
# create_openid
#
# --------------------------------------------------------------------
def create_openid(cluster):
    # eksctl utils associate-iam-oidc-provider --region="$REGION" --cluster="$CLUSTERNAME" --approve # Only run this once
    client = boto3.client('iam')
    try:
        # Create openid connector
        response = client.create_open_id_connect_provider(
            Url=get_oidc_provider(cluster),
            ClientIDList=[
                'sts.amazonaws.com',
            ],
            ThumbprintList=[
                '',
                # https://boto3.amazonaws.com/v1/documentation/api/1.9.42/reference/services/iam.html
            ],
            Tags=[
                {
                    'Key': 'Cluster',
                    'Value': cluster
                },
            ])
        return response['OpenIDConnectProviderArn']
    except:
        # Find the open ID connector
        response = client.list_open_id_connect_providers()
        list_of_oidc = response['OpenIDConnectProviderList']
        for x in list_of_oidc:
            z = client.get_open_id_connect_provider(
                OpenIDConnectProviderArn=x['Arn'])

            if z['Tags'][0]['Value'] == cluster:
                return x['Arn']
            else:
                pass
            

# --------------------------------------------------------------------
#
# create_role
#
# --------------------------------------------------------------------
def create_role(cluster, arcade):
    cluster_name = f"asteroids-{arcade.replace('.', '-')}"
    client = boto3.client('iam')
    d = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": create_openid(cluster_name)
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"oidc.eks.us-east-2.amazonaws.com/id/{create_openid(cluster_name).split('/')[3]}:aud": "sts.amazonaws.com",
                        f"oidc.eks.us-east-2.amazonaws.com/id/{create_openid(cluster_name).split('/')[3]}:sub": f"system:serviceaccount:default:*"
                    }
                }
            }
        ]
    }

    response = client.create_role(
        RoleName=f'{cluster_name}-iamserviceaccount-role',
        AssumeRolePolicyDocument=json.dumps(d))

    account_number = boto3.client('sts').get_caller_identity().get('Account')
    arcade_trim = arcade.split('.')[0]
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        attach = client.attach_role_policy(
            RoleName=f'{cluster_name}-iamserviceaccount-role',
            # TODO Below needs to be updated
            PolicyArn=f'arn:aws:iam::{account_number}:policy/{arcade_trim}-SecretsManager'
            # TODO Above needs to be updated
        )
        if attach['ResponseMetadata']['HTTPStatusCode'] == 200:
            a = create_service_account(arn_role=get_role_for_kube(role_name=f'{cluster_name}-iamserviceaccount-role'), arcade=arcade)
            print(a)
            if a:
                return True
            else:
                return False
        else:
            return False
    else:
        return False
