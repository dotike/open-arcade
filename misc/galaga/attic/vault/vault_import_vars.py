#!/usr/bin/env python3
import boto3
import json
import os
from arclib.common import str_to_bool as str_to_bool
from arclib import ami, grv, storage, secrets_manager


def import_terraform_vars_del(grv_name: str) -> dict:
    session = boto3.session.Session()
    bucket = grv.get_infrastructure_bucket(arcade_name=grv_name)
    vpc_id = grv.get_vpc_id(grv_name=grv_name)
    subnets = grv.find_grv_subnets(gravitar=grv_name)
    cidr = grv.get_vpc_cidr(vpc_id=vpc_id)
    get_az = grv.get_vpc_az(vpc_id=vpc_id, subnet_ids=subnets)
    ami_id = ami.get_ami_id(session, os.getenv('GALAGA_VAULT_NODE_AMI_NAME'))
    zone_id = grv.tld_to_zone_id(os.getenv('GALAGA_VAULT_DOMAIN'))
    zone_arn = f"arn:aws:route53:::hostedzone/{zone_id}"
    vault_tls_SAN_ARN = secrets_manager.get_secret_arn('addaper.net_tls_SAN')

    # Build back out dict for terraform variables in addition to getting the gsd variables
    get_s3_json = storage.load_json(bucket=os.environ.get('GSD_BUCKET'), s3_file_path='galaga/galaga/gsd/vault/latest/latest.json')['service_options']
    get_s3_json['vault_node_ebs_root'] = {}
    get_s3_json['vault_node_ebs_data'] = {}
    get_s3_json['availability_zones'] = get_az
    get_s3_json['vpc_id'] = vpc_id
    get_s3_json['vpc_cidr_block'] = cidr
    get_s3_json['private_subnet_ids'] = subnets
    get_s3_json['vault_node_key_pair'] = f"bootstrap.{grv_name}"
    get_s3_json['ingress_ssh_cidr_blocks'] = [cidr]
    get_s3_json['ingress_vault_cidr_blocks'] = [cidr]
    get_s3_json['owner'] = os.getenv('LOGNAME')
    get_s3_json['s3_bucket_name'] = bucket
    get_s3_json['aws_region'] = os.getenv('AWS_DEFAULT_REGION')
    get_s3_json['route53_zone_id'] = zone_id
    get_s3_json['route53_hosted_zone_arn'] = zone_arn
    get_s3_json['vault_secrets_manager_arn'] = vault_tls_SAN_ARN
    get_s3_json['vault_node_ami_id'] = ami_id
    get_s3_json['vault_node_ebs_root']['volume_type'] = get_s3_json['vault_ebs_root_vol_type']
    get_s3_json['vault_node_ebs_root']['volume_size'] = get_s3_json['vault_ebs_root_vol_size']
    get_s3_json['vault_node_ebs_data']['volume_type'] = get_s3_json['vault_ebs_data_vol_type']
    get_s3_json['vault_node_ebs_data']['volume_size'] = get_s3_json['vault_ebs_data_vol_size']
    get_s3_json['vault_node_ebs_data']['delete_on_termination'] = get_s3_json['vault_vol_delete_on_termination']
    get_s3_json['vault_node_ebs_root']['delete_on_termination'] = get_s3_json['vault_vol_delete_on_termination']
    get_s3_json['vault_node_ebs_data']['encrypted'] = get_s3_json['vault_ebs_vol_encrypted']
    get_s3_json['vault_node_ebs_root']['encrypted'] = get_s3_json['vault_ebs_vol_encrypted']

    return get_s3_json


def import_terraform_vars(grv_name: str) -> dict:
    session = boto3.session.Session()
    bucket = grv.get_infrastructure_bucket(arcade_name=grv_name)
    vpc_id = grv.get_vpc_id(grv_name=grv_name)
    subnets = grv.find_grv_subnets(gravitar=grv_name)
    cidr = grv.get_vpc_cidr(vpc_id=vpc_id)
    get_az = grv.get_vpc_az(vpc_id=vpc_id, subnet_ids=subnets)
    name = f"{grv_name.replace('_', '-').replace('.', ' ').split()[0]}-{os.getenv('GALAGA_CLUSTER_NAME')}"
    ami_id = ami.get_ami_id(session, os.getenv('GALAGA_VAULT_NODE_AMI_NAME'))
    zone_id = grv.tld_to_zone_id(os.getenv('GALAGA_VAULT_DOMAIN'))
    if not zone_id:
        zone_id = 'createnew'
    zone_arn = f"arn:aws:route53:::hostedzone/{zone_id}"
    vault_tls_SAN_ARN = secrets_manager.get_secret_arn('addaper.net_tls_SAN')
    TERRAFORM_VARS = {
        "s3_bucket_name": bucket,
        "cluster_name": name,
        "availability_zones": get_az,
        "vpc_id": vpc_id,
        "aws_region": os.getenv('AWS_DEFAULT_REGION'),
        "vpc_cidr_block": cidr,
        "private_subnet_ids": subnets,
        "vault_domain": os.getenv('GALAGA_VAULT_DOMAIN'),
        "vault_asg_capacity": os.getenv('GALAGA_VAULT_ASG_CAPACITY'),
        "vault_instance_type": os.getenv('GALAGA_VAULT_INSTANCE_TYPE'),
        "vault_node_key_pair": f"bootstrap.{grv_name}",
        "vault_node_ami_id": ami_id,
        "route53_hosted_zone_arn": zone_arn,
        "route53_zone_id": zone_id,
        "ingress_ssh_cidr_blocks": [cidr],
        "ingress_vault_cidr_blocks": [cidr],
        "elb_internal": str_to_bool(os.getenv('GALAGA_ELB_INTERNAL')),
        "owner": os.getenv('LOGNAME'),
        "vault_node_ebs_root": {
            "volume_type": os.getenv('GALAGA_VAULT_EBS_ROOT_VOL_TYPE'),
            "volume_size": int(os.getenv('GALAGA_VAULT_EBS_ROOT_VOL_SIZE')),
            "delete_on_termination": str_to_bool(os.getenv('GALAGA_VAULT_VOL_DELETE_ON_TERMINATION')),
            "encrypted": str_to_bool(os.getenv('GALAGA_VAULT_EBS_VOL_ENCRYPTED'))
        },
        "vault_node_ebs_data": {
            "volume_type": os.getenv('GALAGA_VAULT_EBS_DATA_VOL_TYPE'),
            "volume_size": int(os.getenv('GALAGA_VAULT_EBS_DATA_VOL_SIZE')),
            "delete_on_termination": str_to_bool(os.getenv('GALAGA_VAULT_VOL_DELETE_ON_TERMINATION')),
            "encrypted": str_to_bool(os.getenv('GALAGA_VAULT_EBS_VOL_ENCRYPTED'))
        },
        "vault_secrets_manager_arn": vault_tls_SAN_ARN
    }

    return TERRAFORM_VARS
