# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
narc_rds --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.1'


import asyncio
import boto3
import os
import json
import logging
import time
from botocore.exceptions import ClientError
from arclib import storage, secrets_manager, common, narc_k8s, grv


# --------------------------------------------------------------------
#
# rds_subnets
#
# --------------------------------------------------------------------
def rds_subnets(vpc_id: str) -> list:
    """Generates a list of subnets that are attached to a given VPC.
    Args:
        vpc_id (str): vpc_id ex: vpc-06c72360fbfbcf3b7
    Returns:
        list: list of subnets
    """
    ec2 = boto3.resource('ec2')
    vpc = ec2.Vpc(vpc_id)
    subnet = [x.id for x in vpc.subnets.all()]
    logging.info(f'{subnet} subnets found')
    return subnet


# --------------------------------------------------------------------
#
# create_db_subnetGroup
#
# --------------------------------------------------------------------
def create_db_subnetGroup(arcade_name: str, narc_id: str) -> dict:
    """Creates RDS DB Subnet Group

    Args:
        arcade_name (str): [Name of the ARCADE]
        narc_id (str): [Name of Narc Service]
    Returns:
        dict: [vpcID, subnetGrpArn, Name]
    """
    try:
        rds_client = boto3.client('rds')
        vpc_id = validate_grv_id(grv_id=arcade_name)
        subnets = rds_subnets(vpc_id=vpc_id)
        response = rds_client.create_db_subnet_group(
            DBSubnetGroupName=f'{arcade_name}-{narc_id}-rds-subnetGroup',
            DBSubnetGroupDescription=f'{arcade_name} rds subnet group',
            SubnetIds=find_subnet(subnets=subnets),
            Tags=[
                {
                    'Key': 'Name',
                    'Value': arcade_name
                },
            ])
        return {
            'vpcID': response['DBSubnetGroup']['VpcId'],
            'subnetGrpArn': response['DBSubnetGroup']['DBSubnetGroupArn'],
            'Name': response['DBSubnetGroup']['DBSubnetGroupName']
        }
    except ClientError as e:
        return e


# --------------------------------------------------------------------
#
# get_db_subnet_group
#
# --------------------------------------------------------------------
def get_db_subnet_group(arcade_name: str, narc_id: str) -> dict:
    """Gets existing db subnet group.  If it doesn't exist just return None

    Args:
        arcade_name (str): [Name of the ARCADE]
        narc_id (str): [Name of Narc Service]

    Returns:
        dict: [vpcID, subnetGrpArn, Name]
    """
    try:
        rds_client = boto3.client('rds')
        response = rds_client.describe_db_subnet_groups(
            DBSubnetGroupName=f"{arcade_name}-{narc_id}-rds-subnetgroup",
        )

        return {
            'vpcID': response['DBSubnetGroups'][0]['VpcId'],
            'subnetGrpArn': response['DBSubnetGroups'][0]['DBSubnetGroupArn'],
            'Name': response['DBSubnetGroups'][0]['DBSubnetGroupName']
        }
    except:
        return None


# --------------------------------------------------------------------
#
# get_lambsa_status
#
# --------------------------------------------------------------------
def get_lambda_status(function_name: str):
    lambda_client = boto3.client('lambda')
    response = lambda_client.get_function(FunctionName=function_name)
    return response['Configuration']['State']


# --------------------------------------------------------------------
#
# create_rds_instance_aprallel
#
# --------------------------------------------------------------------
async def create_rds_instance_parallel(arcade_name: str, asd_data):
    # TODO Change back to Multi AZ for HA
    # TODO Investigate backups
    """Create a RDS instance with Multi AZ HA set up.

    Args:
        arcade_name (str): [Name of the arcade]
        asd_data ([type]): [asd data from narc]

    Returns:
        [str]: [json information on the build of the RDS instance]
    """
    lambda_status = []
    status_list = []
    try:
        default_creds = json.loads(secrets_manager.get_secret(arcade_name=arcade_name, name='rds_default_credentials'))
        my_session = common.setup_arcade_session(arcade_name)
        app_bucket = storage.get_arcade_buckets(my_session, arcade_name)['infrastructure']
        my_region = my_session.region_name
        multiaz = asd_data['containers'][0]['multiAZ']
        narc_id = asd_data['service']
        logging.info(f"NARC ID: {narc_id}")
        asteroid_name = narc_id.replace('-', ' ').split()[1]
        logging.info(f"ASTEROID NAME: {asteroid_name}")
        db_identifier = narc_id.replace('.', '').replace('_', '')
        logging.info(f"DB identifier: {db_identifier}")
        rds_client = my_session.client('rds')
        allocated_storage = asd_data['containers'][0]['storage']
        db_instance_class = asd_data['containers'][0]['instance_type']
        db_engine = asd_data['containers'][0]['engine']
        db_engine_version = asd_data['containers'][0]['engine_version']
        db_name = narc_id.replace('-', '')
        logging.info(f"DB NAME: {db_name}")

        # If DB Subnet Group Exists...
        db_subnet_grp_name = get_db_subnet_group(arcade_name=arcade_name, narc_id=narc_id)
        if db_subnet_grp_name is None:
            db_subnet_grp_name = create_db_subnetGroup(arcade_name=arcade_name, narc_id=narc_id)

        response = rds_client.create_db_instance(
            DBName=f"{db_name}rds",
            DBInstanceIdentifier=db_identifier,
            AllocatedStorage=allocated_storage,
            DBInstanceClass=db_instance_class,
            Engine=db_engine,
            EngineVersion=db_engine_version,
            DBParameterGroupName=f"arcade-rds-pg",
            MultiAZ=multiaz,
            Tags=[
                {
                    'Key': 'grv_name',
                    'Value': arcade_name
                },
                {
                    'Key': 'asteroid_name',
                    'Value': asteroid_name
                },
            ],
            DBSubnetGroupName=db_subnet_grp_name['Name'],
            MasterUsername=default_creds['username'],
            MasterUserPassword=default_creds['password'],
            VpcSecurityGroupIds=[
                grv.check_if_sg(sg_name=f'data_rds.{arcade_name}'),
            ])
        status = get_db_status(db_instance_identifier=db_identifier)
        status_list.insert(0, str(status))

        while status_list[0] == 'creating' or status_list[0] == 'backing-up' or status_list[0] == 'modifying':
            await asyncio.sleep(1)
            new_status = get_db_status(db_instance_identifier=db_identifier)
            if status_list[0] == 'creating' or status_list[0] == 'backing-up' or status_list[0] == 'modifying':
                status_list.insert(0, new_status)
                continue
            if status_list[0] == 'available':
                break

        ###################### BEGIN SCHEMA LOAD LAMBDA ###############################################################
        # NOTE: Removing the autoloading of database schemas until we decide how we want to handle that sort of thing
        #       We will likely want the json to specify an optional "schema" directive where the user can pick from some
        #       schema offerings and those would be loaded.  The default should be no schema.

        #await asyncio.sleep(120)
        #a = rds_import_lambda(my_session, arcade_name, narc_id)
        #logging.info(a)
        #starting_lambda_status = get_lambda_status(f'{narc_id}-lambda')
        #lambda_status.insert(0, starting_lambda_status)
        #while lambda_status[0] == 'Pending' or lambda_status[0] == 'Inactive' or lambda_status[0] == 'Failed' or lambda_status[0] == 'Active':
        #    await asyncio.sleep(1)
        #    new_status = get_lambda_status(f'{narc_id}-lambda')
        #    if lambda_status[0] == 'Active':
        #        break
        #    if lambda_status[0] == 'Pending' or lambda_status[0] == 'Inactive' or lambda_status[0] == 'Failed':
        #        lambda_status.insert(0, new_status)
        #        continue

        #get_endpoint = rds_client.describe_db_instances(DBInstanceIdentifier=response['DBInstance']['DBInstanceIdentifier'])
        #data_payload = {
        #    'DBNAME': get_endpoint.get('DBInstances')[0].get('Endpoint').get('Address'),
        #    'USERNAME': default_creds['username'],
        #    'PASSWORD': default_creds['password'],
        #    'Bucket': app_bucket
        #}
        #a = invoke_lambda(
        #    session=my_session,
        #    function_name=f'{narc_id}-lambda',
        #    payload=data_payload,
        #)
        #logging.info(json.dumps(a, sort_keys=True, indent=4, default=str))

        ###################### END SCHEMA LOAD LAMBDA #################################################################

        instances = rds_client.describe_db_instances(DBInstanceIdentifier=response['DBInstance']['DBInstanceIdentifier'])
        rds_hostname = instances.get('DBInstances')[0]['Endpoint']['Address']
        logging.info(f"RDS HOSTNAME: {rds_hostname}")
        narc_k8s.create_external_named_service(arcade_name, rds_hostname, narc_id, asteroid_name)
        return f"{narc_id} RDS instance has been created"

    except ClientError as e:
        logging.error(f"RDS Client Error: {e}")
        return e


# --------------------------------------------------------------------
#
# create_rds_instance_serial
#
# --------------------------------------------------------------------
def create_rds_instance_serial(arcade_name: str, asd_data):
    # TODO Change back to Multi AZ for HA
    # TODO Investigate backups
    """Create a RDS instance with Multi AZ HA set up.

    Args:
        arcade_name (str): [Name of the arcade]
        asd_data ([type]): [asd data from narc]

    Returns:
        [str]: [json information on the build of the RDS instance]
    """
    lambda_status = []
    status_list = []
    try:
        default_creds = json.loads(secrets_manager.get_secret(arcade_name=arcade_name, name='rds_default_credentials'))
        my_session = common.setup_arcade_session(arcade_name)
        app_bucket = storage.get_arcade_buckets(my_session, arcade_name)['infrastructure']
        my_region = my_session.region_name
        multiaz = asd_data['containers'][0]['multiAZ']
        narc_id = asd_data['service']
        logging.info(f"NARC ID: {narc_id}")
        asteroid_name = narc_id.replace('-', ' ').split()[1]
        logging.info(f"ASTEROID NAME: {asteroid_name}")
        db_identifier = narc_id.replace('.', '').replace('_', '')
        logging.info(f"DB identifier: {db_identifier}")
        rds_client = my_session.client('rds')
        allocated_storage = asd_data['containers'][0]['storage']
        db_instance_class = asd_data['containers'][0]['instance_type']
        db_engine = asd_data['containers'][0]['engine']
        db_engine_version = asd_data['containers'][0]['engine_version']
        db_name = narc_id.replace('-', '')
        logging.info(f"DB NAME: {db_name}")

        # If DB Subnet Group Exists...
        db_subnet_grp_name = get_db_subnet_group(arcade_name=arcade_name, narc_id=narc_id)
        if db_subnet_grp_name is None:
            db_subnet_grp_name = create_db_subnetGroup(arcade_name=arcade_name, narc_id=narc_id)

        response = rds_client.create_db_instance(
            DBName=f"{db_name}rds",
            DBInstanceIdentifier=db_identifier,
            AllocatedStorage=allocated_storage,
            DBInstanceClass=db_instance_class,
            Engine=db_engine,
            EngineVersion=db_engine_version,
            DBParameterGroupName=f"arcade-rds-pg",
            MultiAZ=multiaz,
            Tags=[
                {
                    'Key': 'grv_name',
                    'Value': arcade_name
                },
                {
                    'Key': 'asteroid_name',
                    'Value': asteroid_name
                },
            ],
            DBSubnetGroupName=db_subnet_grp_name['Name'],
            MasterUsername=default_creds['username'],
            MasterUserPassword=default_creds['password'],
            VpcSecurityGroupIds=[
                grv.check_if_sg(sg_name=f'data_rds.{arcade_name}'),
            ])
        status = get_db_status(db_instance_identifier=db_identifier)
        status_list.insert(0, str(status))

        while status_list[0] == 'creating' or status_list[0] == 'backing-up' or status_list[0] == 'modifying':
            time.sleep(1)
            new_status = get_db_status(db_instance_identifier=db_identifier)
            if status_list[0] == 'creating' or status_list[0] == 'backing-up' or status_list[0] == 'modifying':
                status_list.insert(0, new_status)
                continue
            if status_list[0] == 'available':
                break

        ###################### BEGIN SCHEMA LOAD LAMBDA ###############################################################
        # NOTE: Removing the autoloading of database schemas until we decide how we want to handle that sort of thing
        #       We will likely want the json to specify an optional "schema" directive where the user can pick from some
        #       schema offerings and those would be loaded.  The default should be no schema.

        #time.sleep(120)
        #a = rds_import_lambda(my_session, arcade_name, narc_id)
        #logging.info(a)
        #starting_lambda_status = get_lambda_status(f'{narc_id}-lambda')
        #lambda_status.insert(0, starting_lambda_status)
        #while lambda_status[0] == 'Pending' or lambda_status[0] == 'Inactive' or lambda_status[0] == 'Failed' or lambda_status[0] == 'Active':
        #    time.sleep(1)
        #    new_status = get_lambda_status(f'{narc_id}-lambda')
        #    if lambda_status[0] == 'Active':
        #        break
        #    if lambda_status[0] == 'Pending' or lambda_status[0] == 'Inactive' or lambda_status[0] == 'Failed':
        #        lambda_status.insert(0, new_status)
        #        continue

        #get_endpoint = rds_client.describe_db_instances(DBInstanceIdentifier=response['DBInstance']['DBInstanceIdentifier'])
        #data_payload = {
        #    'DBNAME': get_endpoint.get('DBInstances')[0].get('Endpoint').get('Address'),
        #    'USERNAME': default_creds['username'],
        #    'PASSWORD': default_creds['password'],
        #    'Bucket': app_bucket
        #}
        #a = invoke_lambda(
        #    session=my_session,
        #    function_name=f'{narc_id}-lambda',
        #    payload=data_payload,
        #)
        #logging.info(json.dumps(a, sort_keys=True, indent=4, default=str))

        ###################### END SCHEMA LOAD LAMBDA #################################################################

        instances = rds_client.describe_db_instances(DBInstanceIdentifier=response['DBInstance']['DBInstanceIdentifier'])
        rds_hostname = instances.get('DBInstances')[0]['Endpoint']['Address']
        logging.info(f"RDS HOSTNAME: {rds_hostname}")
        narc_k8s.create_external_named_service(arcade_name, rds_hostname, narc_id, asteroid_name)
        return f"{narc_id} RDS instance has been created"

    except ClientError as e:
        logging.error(f"RDS Client Error: {e}")
        return e


# --------------------------------------------------------------------
#
# delete_rds_resource_parallel
#
# --------------------------------------------------------------------
async def delete_rds_resource_parallel(arcade_name: str, narc_id: str):
    status_list = []
    try:
        db_identifier = narc_id.replace('.', '').replace('_', '')
        rds_client = boto3.client('rds')
        status = get_db_status(db_instance_identifier=db_identifier)
        status_list.insert(0, str(status))
        response = rds_client.delete_db_instance(
            DBInstanceIdentifier=db_identifier,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True
        )

        while status_list[0] == 'deleting' or status_list[0] == 'available' or status_list[0] == 'backing-up':

            new_status = get_db_status(db_instance_identifier=db_identifier)

            if status_list[0] == 'deleting' or status_list[0] == 'available' or status_list[0] == 'backing-up':
                # print('Still deleting')
                status_list.insert(0, new_status)
                continue

            if status_list[0] == 'Deleted':
                break

        delete_subnet_grp = delete_rds_subnet_grp(
            db_subnetgrp_name=response['DBInstance']['DBSubnetGroup']['DBSubnetGroupName'])

        # Remove named service object
        asteroid_name = narc_id[len('narc-'):narc_id.find('-', narc_id.find('-') + 1)]
        narc_k8s.delete_external_named_service(arcade_name, narc_id, asteroid_name)
        # NOTE: Until we need the lambda to load schema don't need to delete it
        #delete_lambda(function_name=f'{narc_id}-lambda')
        return f"RDS instance {narc_id} is deleted"
    except ClientError as e:
        return e


# --------------------------------------------------------------------
#
# delete_rds_subnet_grp
#
# --------------------------------------------------------------------
def delete_rds_subnet_grp(db_subnetgrp_name: str):
    """Delete RDS Subnet Group.

    Args:
        db_subnetgrp_name (str): [Name of the rds subnet group]

    Returns:
        [dict]: [Delete Response]
    """
    try:
        rds_client = boto3.client('rds')
        response = rds_client.delete_db_subnet_group(DBSubnetGroupName=db_subnetgrp_name)
        return response
    except ClientError as e:
        return e


# --------------------------------------------------------------------
#
# validate_grv_id
#
# --------------------------------------------------------------------
def validate_grv_id(grv_id: str):
    try:
        ec2_client = boto3.client('ec2')
        if not grv_id == '':
            try:
                # straight for the answer,
                response = ec2_client.describe_vpcs(
                    DryRun=False,
                    VpcIds=[grv_id]
                )['Vpcs'][0]['VpcId']

            except Exception as err1:
                # filter query to keep it light payload,
                try:
                    vlist = ec2_client.describe_vpcs(
                        DryRun=False,
                        Filters=[{'Name': 'tag:Name', 'Values': [grv_id]}, ],
                    )['Vpcs']
                    # now uplack that result and straight for the answer again,
                    if len(vlist) == 1:
                        # this is the common case
                        response = vlist[0]['VpcId']
                    # if that didn't work, do we have any results?
                    elif not vlist:
                        msg = "No 'grv_id' in AWS with tag:Name or Object ID '{}'".format(
                            grv_id)
                        raise ValueError(msg)
                    # finally, we must have too many results, (rare and broken case),
                    else:
                        response = []
                        for avpc in vlist:
                            response.append(avpc['VpcId'])

                except Exception as err2:
                    emsg = "AWS or boto error: {0}: {1}".format(err1, err2)
                    raise EnvironmentError(emsg)
        else:
            vmsg = "validate_grv_id() given '{}', does not handle empty string grv names.".format(grv_id)
            raise ValueError(vmsg)

        return response

    except Exception as err:
        raise type(err)('validate_grv_id(): {}'.format(err))


# --------------------------------------------------------------------
#
# find_subnet
#
# --------------------------------------------------------------------
def find_subnet(subnets: list) -> list:
    """Find Subnets that are for use with EKS
    Args:
        subnets (list): [list of subnets]
    Returns:
        [list]: [subnets for use with EKS]
    """
    ec2 = boto3.resource('ec2')
    found_subnets = []
    for data in subnets:
        subnet = ec2.Subnet(data)
        arcade_name = find_vpc_name(subnet.vpc_id).replace("_", "-")
        for s in subnet.tags:
            if s['Value'] == f'data.{arcade_name}':
                found_subnets.append(subnet.subnet_id)

    logging.info(f'found subnets {found_subnets}')
    return found_subnets


# --------------------------------------------------------------------
#
# find_vpc_name
#
# --------------------------------------------------------------------
def find_vpc_name(vpc_id: str) -> str:
    """Find the VPC NAME TAG for a given VPC
    Args:
        vpc_id ([str]): The VPC Id
    Returns:
        [str]: vpc name tag
    """
    ec2 = boto3.resource('ec2')
    vpc = ec2.Vpc(vpc_id)
    for items in vpc.tags:
        if items['Key'] == 'Name':
            logging.info(f"vpc name has been found")
            return items['Value']


# --------------------------------------------------------------------
#
# get_rds_instances
#
# --------------------------------------------------------------------
def get_rds_instances() -> list:
    """Returns a list of RDS instances

    Returns:
        [list]: [List of RDS instances]
    """
    rds_client = boto3.client('rds')
    response = rds_client.describe_db_instances()
    instance_ids = [x['DBInstanceIdentifier']for x in response['DBInstances']]
    instance_list = []
    for instance in instance_ids:
        if 'narc-' in instance:
            instance_list.append(instance.replace('narc-', ''))
    return instance_list


# --------------------------------------------------------------------
#
# get_db_status
#
# --------------------------------------------------------------------
def get_db_status(db_instance_identifier: str):
    """Gets the status of the created or deleting database
    'deleting', 'available', 'backing-up', 'avaliable' are the status that aws provides

    Args:
        db_instance_identifier (str): [db instance identifier]

    Returns:
        [str]: [status of the database]
    """
    rds_client = boto3.client('rds')
    try:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
        return response['DBInstances'][0]['DBInstanceStatus']
    except rds_client.exceptions.DBInstanceNotFoundFault as e:
        return 'Deleted'


# --------------------------------------------------------------------
#
# upload_lambda
#
# --------------------------------------------------------------------
def upload_lambda(session: boto3.session.Session, arcade_name: str, name: str, path: str, s3_path: str):
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
# delete_lambda
#
# --------------------------------------------------------------------
def delete_lambda(function_name: str):
    lambda_client = boto3.client('lambda')
    response = lambda_client.delete_function(FunctionName=function_name)
    return response


# --------------------------------------------------------------------
#
# invoke_lambda
#
# --------------------------------------------------------------------
def invoke_lambda(session: boto3.session.Session, function_name: str, payload: dict):
    lambda_client = session.client('lambda')
    response = lambda_client.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload),
    )
    return response


# --------------------------------------------------------------------
#
# rds_import_lambda
#
# --------------------------------------------------------------------
def rds_import_lambda(session: boto3.session.Session, arcade_name: str, narc_id: str):
    account_number = session.client('sts').get_caller_identity().get('Account')
    app_bucket = storage.get_arcade_buckets(session, arcade_name)['infrastructure']
    vpc_id = validate_grv_id(grv_id=arcade_name)
    lambda_client = session.client('lambda')
    lambda_functions_path = f"{os.environ['MYHIER']}/libexec/lambda_functions"
    push_lambda = upload_lambda(session, arcade_name, 'db.py.zip', lambda_functions_path, 'arcade_db/lambda/db.py.zip')
    logging.info(push_lambda)
    push_schema = upload_lambda(session, arcade_name, 'empty_asteroid_backup.sql', lambda_functions_path, 'arcade_db/empty_asteroid_backup.sql')
    logging.info(push_schema)
    response = lambda_client.create_function(
        FunctionName=f"{narc_id}-lambda",
        Runtime='python3.8',
        # TODO Role needs a function to create on the fly
        Role=f'arn:aws:iam::{account_number}:role/lambda-vpc-role',
        Handler='db.lambda_handler',
        Code={
            'S3Bucket': app_bucket,
            'S3Key': 'arcade_db/lambda/db.py.zip',
        },
        Description='Function that sets DB schema for ARCADDB',
        Timeout=120,
        MemorySize=128,
        PackageType='Zip',
        Publish=True,
        VpcConfig={
            'SubnetIds': find_subnet(rds_subnets(vpc_id=vpc_id)),
            'SecurityGroupIds': [grv.check_if_sg(sg_name=f'data_rds.{arcade_name}')]
        }
    )
    logging.info(f'Lambda Response: {json.dumps(response, sort_keys=True, indent=4, default=str)}')
    return response
