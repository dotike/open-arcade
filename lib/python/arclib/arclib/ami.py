# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
ami -- 
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import boto3
import logging
import time

from arclib import grv, common
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError

# --------------------------------------------------------------------
#
# get_ami_id
#
# --------------------------------------------------------------------
def get_ami_id(session: boto3.session.Session, ami_name: str) -> str:
    """Get ami id using the AMI name.

    Args:
        session: boto3 session
        ami_name: name of the AMI

    Returns:
        str: AMI id
    """
    client = session.client('ec2')
    response = client.describe_images(
        Filters=[
            {
                'Name': 'name',
                'Values': [ami_name]
            },
        ],
    )

    return response['Images'][0]['ImageId']


# --------------------------------------------------------------------
#
# ami_info
#
# --------------------------------------------------------------------
def ami_info(session: boto3.session.Session,
             ami_id: str) -> dict:
    """
    Describe AMI information.

    Args:
        session: boto3 session
        ami_id: AMI id

    Returns:
        dict: AMI information
    """
    client = session.client('ec2')
    response = client.describe_images(ImageIds=[ami_id])

    return response['Images'][0]


# --------------------------------------------------------------------
#
# wait_fir_ami_availability
#
# --------------------------------------------------------------------
def wait_for_ami_availability(session: boto3.session.Session,
                              ami_id: str):
    """Wait for the ami to become available.

    Args:
        session: boto3 session
        ami_id: AMI id
    Returns:
        None:
    """
    print(f'Waiting for AMI {ami_id} to become available')
    status = ami_info(session, ami_id)['State']
    while status != 'available':
        time.sleep(30)
        status = ami_info(session, ami_id)['State']
        print('Waiting')

    return


# --------------------------------------------------------------------
#
# list_amis
#
# --------------------------------------------------------------------
def list_amis(session: boto3.session.Session) -> list:
    """
    List AMIs available.

    Args:
        session: boto3 session

    Returns:
        list: list of AMIs available in AWS
    """
    client = session.client('ec2')
    response = client.describe_images(Owners=['self'])
    # pprint(response)
    image_list = []
    for image in response['Images']:
        image_list.append({"Name": image['Name'], "ImageId": image['ImageId'], "CreationDate": image['CreationDate']})

    return sorted(image_list, key=lambda x: x['Name'])
    # pprint(sorted(image_list, key=lambda x: (x[2], x[0]), reverse=False))


# --------------------------------------------------------------------
#
# list_images_in_s3
#
# --------------------------------------------------------------------
def list_images_in_s3(session: boto3.session.Session,
                      bucket: str,
                      path: str) -> list:
    """
    List images in S3.

    Args:
        session: boto3 session
        bucket: the S3 bucket
        path: the S3 key

    Returns:
        dict: AMI information
    """
    s3_client = session.client('s3')
    response = s3_client.list_objects_v2(
        Bucket=bucket,
        Prefix=path
    )
    image_list = []
    for image in response['Contents']:
        image_list.append({"Name": image['Key'].split("/").pop(), "Path": f"{bucket}/{path}", "Size": image['Size']})

    return sorted(image_list, key=lambda x: x['Name'])


# --------------------------------------------------------------------
#
# export_ami
#
# --------------------------------------------------------------------
def export_ami(session: boto3.session.Session,
               ami_id: str,
               bucket: str,
               path: str,
               role_name: str):
    """
    Export AMI to S3.

    Args:
        session: boto3 session
        ami_id: AMI id
        bucket: the S3 bucket
        path: the S3 key
        role_name: the role to do the export as(vmimport)

    Returns:
        None: no return
    """
    client = session.client('ec2')
    s3_client = session.client('s3')
    image_name = ami_info(session, ami_id)['Name']
    try:
        response = client.export_image(
            DiskImageFormat='VMDK',
            ImageId=ami_id,
            S3ExportLocation={
                'S3Bucket': bucket,
                'S3Prefix': path
            },
            RoleName=role_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceCountExceeded':
            print(e.response['Error']['Message'])
            return
    logging.debug(response)
    export_image_task_id = response['ExportImageTaskId']
    status = response['Status']
    while status != 'completed':
        time.sleep(60)
        describe_response = client.describe_export_image_tasks(
            ExportImageTaskIds=[export_image_task_id])
        status = describe_response['ExportImageTasks'][0]['Status']
        print(f"export {status}")
    s3_copy_response = s3_client.copy_object(Bucket=bucket,
                                             CopySource=f"{bucket}/{path}{export_image_task_id}.vmdk",
                                             Key=f"{path}{image_name}.vmdk".replace(' ', '-'))
    # pprint(s3_response)
    s3_delete_response = s3_client.delete_object(Bucket=bucket, Key=f"{path}{export_image_task_id}.vmdk")
    print(f"exported ami {bucket}/{path}{export_image_task_id}.vmdk")
    print(f"named ami {bucket}/{path}{image_name}.vmdk")

    return


# --------------------------------------------------------------------
#
# import_image
#
# --------------------------------------------------------------------
def import_image(session: boto3.session.Session,
                 image_name: str,
                 bucket: str,
                 path: str,
                 role_name: str) -> str:
    """
    Import image from S3.

    Args:
        session: boto3 session
        image_name: Image name
        bucket: the S3 bucket
        path: the S3 key
        role_name: the role to do the export as(vmimport)

    Returns:
        str: the AMI id
    """
    ec2_client = session.client('ec2')
    image_format = image_name.split('.').pop().upper()
    response = ec2_client.import_image(
        Description=image_name,
        DiskContainers=[
            {
                'Description': image_name,
                'Format': image_format,
                'UserBucket': {
                    'S3Bucket': bucket,
                    'S3Key': f"{path}{image_name}"
                }
            },
        ],
        RoleName=role_name,
    )
    logging.debug(response)
    import_image_task_id = response['ImportTaskId']
    status = response['Status']
    while status != 'completed':
        time.sleep(60)
        describe_response = ec2_client.describe_import_image_tasks(
            ImportTaskIds=[import_image_task_id])
        status = describe_response['ImportImageTasks'][0]['Status']
        print(f"import {status}")
    import_image_id = describe_response['ImportImageTasks'][0]['ImageId']
    import_image_region = session.region_name
    copy_response = ec2_client.copy_image(
        Description=image_name,
        Name=image_name.replace(f".{image_format.lower()}", ''),
        SourceImageId=import_image_id,
        SourceRegion=import_image_region,
    )
    real_image_id = copy_response['ImageId']
    logging.debug(copy_response)
    deregister_response = ec2_client.deregister_image(ImageId=import_image_id)
    logging.debug(deregister_response)
    tag_response = ec2_client.create_tags(
        Resources=[real_image_id],
        Tags=[
            {
                'Key': 'Name',
                'Value': image_name.replace(f".{image_format.lower()}", '')
            },
        ]
    )
    logging.debug(tag_response)
    print(f"AMI id {real_image_id}")

    return real_image_id


# --------------------------------------------------------------------
#
# copy_ami
#
# --------------------------------------------------------------------
def copy_ami(session: boto3.session.Session,
             ami_id: str,
             region_list: list) -> bool:
    """
    Copy AMI across regions.

    Args:
        session: boto3 session
        ami_id: AMI id
        region_list: list of regions to copy AMI to

    Returns:
        bool: success or fail
    """
    ec2_client = session.client('ec2')
    region_name = session.region_name
    if region_name in region_list:
        region_list.remove(region_name)
    image_info = ami_info(session, ami_id)
    if image_info['State'] != 'available':
        print(f"AMI {ami_id} is not available to copy")
        return False
    image_name = image_info['Name']
    if len(image_info['Tags']) != 0:
        image_tag_name = common.aws_tags_dict(image_info['Tags'])['Name']
    else:
        image_tag_name = image_name
    for region in region_list:
        copy_client = session.client('ec2', region_name=region)
        copy_response = copy_client.copy_image(
            Description=image_name,
            Name=image_name,
            SourceImageId=ami_id,
            SourceRegion=region_name
        )
        logging.debug(copy_response)
        real_image_id = copy_response['ImageId']
        tag_response = copy_client.create_tags(
            Resources=[real_image_id],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': image_tag_name
                },
            ]
        )
        print(f"AMI {ami_id} copied to region {region}")

    return True


# --------------------------------------------------------------------
#
# get_vmimport_role
#
# --------------------------------------------------------------------
def get_vmimport_role(session: boto3.session.Session,
                      bucket: str) -> str:
    """
    Get or create the vmimport role.

    Args:
        session: boto3 session
        bucket: bucket to use for vmimport

    Returns:
        str: role_name
    """
    # role and policy need to be called vmimport for things to work.
    arcade_vmimport_role = "vmimport"
    arcade_vmimport_policy = "vmimport"

    # bucket_name = "asd-1232114"
    ARCADE_VMIMPORT_ASSUME_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "vmie.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:Externalid": arcade_vmimport_role
                    }
                }
            }
        ]
    }

    ARCADE_VMIMPORT_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:PutObject",
                    "s3:GetBucketAcl"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:ModifySnapshotAttribute",
                    "ec2:CopySnapshot",
                    "ec2:RegisterImage",
                    "ec2:Describe*"
                ],
                "Resource": "*"
            }
        ]
    }

    # pprint(ACCOUNT_VMIMPORT_POLICY)
    # print('')
    # pprint(ACCOUNT_VMIMPORT_ASSUME_POLICY)

    role_dict = grv.find_role(arcade_vmimport_role)
    if role_dict != {}:
        role_arn = role_dict['Role']['Arn']
        # print("Account VM import role already exists")
    else:
        policy_arn = grv.create_policy(arcade_vmimport_policy, ARCADE_VMIMPORT_POLICY)
        arcade_vmimport_policy_arns = [policy_arn]
        role_arn = grv.create_role(arcade_vmimport_role,
                                   arcade_vmimport_policy_arns,
                                   ARCADE_VMIMPORT_ASSUME_POLICY)
        print("Account VM import role created")

    return arcade_vmimport_role
