# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
tags -- handles tagging functionality
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.1'

import boto3
from botocore.exceptions import ClientError
import re
from string import Template
import logging

from arclib import common
from arclib import inventory as inv

# list of resources for whom standard tagging is not an option
tagging_not_standard = [
    "hostedzone"
]

# resource_type : service
resource_table = {
    "autoScalingGroup": "autoscaling",
    "instance": "ec2",
    "volume": "ec2",
    "internet-gateway": "ec2",
    "network-acl": "ec2",
    "network-interface": "ec2",
    "route-table": "ec2",
    "security-group": "ec2",
    "vpc": "ec2",
    "vpc-endpoints": "ec2",
    "subnet": "ec2",
    "elastic-ip": "ec2",
    "natgateway": "ec2",
    "cluster": "eks",
    "nodegroup": "eks",
    "hostedzone": "route53",
    "loadbalancer": "elasticloadbalancing",
    "targetgroup": "elasticloadbalancing",
    "secret": "secretsmanager", 
    "msk": "kafka",
    "parameter": "ssm",
    "rds_instance": "rds",
    "subgrp": "rds",
    "function": "lambda"
}

# --------------------------------------------------------------------
#
# gen_arn
#
# --------------------------------------------------------------------


def gen_arn(account_id, resource_type, resource_id, region="",
            extra_name="", service="") -> str:
    """
    Given a service type and other needed info, returns the properly
    formatted AWS ARN.
    """
    # service_resource_type : formatStr
    base = "arn:aws:"
    default = Template(
        "${service}:${region}:${account_id}:${resource_type}/${resource_id}")
    # resource_type: format
    formats = {
        "autoScalingGroup": Template(
            "${service}:${region}:${account_id}:${resource_type}:\
            ${resource_id}${GroupId}:autoScalingGroupName/${extra_name}"),
        "instance": default,
        "volume": default,
        "internet-gateway": default,
        "network-acl": default,
        "network-interface": default,
        "route-table": default,
        "security-group": default,
        "vpc": default,
        "vpc-endpoints": default,
        "s3": Template("s3:::${resource_id}"),  # specifically, this is buckets
        "subnet": default,
        "elastic-ip": default,
        "natgateway": default,
        "cluster": default,
        "function": Template("lambda:${region}:${account_id}:function:${resource_id}"),
        "rds_instance": Template("rds:${region}:${account_id}:db:${resource_id}"),
        "subgrp": Template("rds:${region}:${account_id}:subgrp:${resource_id}"),
#        not needed for now because we get arn directly from inventory:
#        "nodegroup": Template("eks:${region}:${account_id}:\
#           ${resource_type}/${extra_name}/${resource_id}/*"),  # we'll see if this works; otherwise will need uuid
        "hostedzone": Template("route53:::${resource_type}/${resource_id}"),
        "healthcheck": Template("route53:::${resource_type}/${resource_id}"),
        "loadbalancer": Template("elasticloadbalancing:${region}:\
            ${account_id}:${resource_type}/app/${extra_name}/${resource_id}"),
        "targetgroup": default,
        "secret": Template("${service}:${region}:${account_id}:\
            ${resource_type}:${resource_id}"),
        "parameter": Template("${service}:${region}:${account_id}:\
            ${resource_type}/${resource_id}")
    }

    # do some extra processing
    if not service:
        service = _service_lookup(resource_type)

    if resource_type not in formats.keys():
        logging.warning(f"{resource_type} not valid")
        return ""

    return (base + formats[resource_type].substitute(
        service=service, region=region, account_id=account_id,
        resource_type=resource_type, resource_id=resource_id,
        extra_name=extra_name
    )).replace(' ', '')  # it treats the arguments as a dict, so it will ignore extras

# --------------------------------------------------------------------
#
# service_lookup
#
# --------------------------------------------------------------------


def _service_lookup(resource_type):
    if resource_type in resource_table.keys():
        return resource_table[resource_type]
    else:
        return ""


def get_arcade_resource_arns(arcade_name):
    # use inventory tool to get everything
    resources = inv.get_resource_info(arcade_name=arcade_name,
                                      inclusive=False, layer="arcade")
    # Passing GRV Not Found up the chain
    if resources == arcade_name:
        return arcade_name
    # loop through and get ARNs
    arns = {}
    account = common.get_account_id()
    region = common.get_arcade_region(arcade_name)
    if not resources:
        return {}
    for key, resource_data in resources.items():  # this does most of the heavy lifting
        if key == "auto_scale_groups" and resources[key]:
            for entry in resources[key]:
                arns[entry["AutoScalingGroupARN"]] = "autoScalingGroup"
        elif key == "ec2_instance" and resources[key]:
            for entry in resources[key]:
                instances = entry["Instances"]
                for instance in instances:
                    inst_arn = gen_arn(account_id=account, resource_type="instance", resource_id=instance["InstanceId"],
                                       region=region)
                    arns[inst_arn] = "instance"
                    for device in instance["BlockDeviceMappings"]:
                        vol_arn = gen_arn(account_id=account, resource_type="volume",
                                          resource_id=device['Ebs']['VolumeId'], region=region)
                        arns[vol_arn] = "volume"
        elif key == "eks_cluster" and resources[key]:
            arn = resource_data["arn"]
            arns[arn] = "cluster"
        elif key == "eks_nodegroup_arn" and resources[key]:
            arn = resource_data
            arns[arn] = "nodegroup"
        elif key == "eips" and resources[key]:
            for entry in resources[key]:
                arn = entry["ResourceARN"]
                arns[arn] = "elastic-ip"
        elif key == "hosted_zone" and resources[key]:
            res_id = resource_data["Id"].split("/")[-1]
            arn = gen_arn(account_id=account, resource_type="hostedzone",
                          resource_id=res_id, region=region)
            arns[arn] = "hostedzone"
        elif key == "healthcheck" and resources[key]:
            for check in resource_data:
                arn = gen_arn(account_id=account, resource_type="healthcheck",
                              resource_id=check["Id"], region=region)
                arns[arn] = "healthcheck"
        elif key == "internet_gateways" and resources[key]:
            for igw in resource_data:
                arn = gen_arn(account_id=account, resource_type="internet-gateway", resource_id=igw["InternetGatewayId"],
                              region=region)
                arns[arn] = "internet-gateway"
        elif key == "lambda_functions" and resources[key]:
            for func in resource_data:
                arn = func["FunctionArn"]
                arns[arn] = "lambda"
        elif key == "load_balancer" and resources[key]:
            for lb in resource_data:
                arn = lb["LoadBalancerArn"]
                arns[arn] = "loadbalancer"
        elif key == "msk" and resources[key]:
            arn = resource_data["ClusterArn"]
            arns[arn] = "msk"
        elif key == "nat_gateways" and resources[key]:
            for ngw in resource_data:
                arn = gen_arn(account_id=account, resource_type="natgateway",
                              resource_id=ngw["NatGatewayId"], region=region)
                arns[arn] = "natgateway"
        elif key == "network_acl" and resources[key]:
            for acl in resource_data:
                arn = gen_arn(account_id=account, resource_type="network-acl",
                              resource_id=acl["NetworkAclId"], region=region)
                arns[arn] = "network-acl"
        elif key == "network_interfaces" and resources[key]:
            for iface in resource_data:
                arn = gen_arn(account_id=account, resource_type="network-interface",
                              resource_id=iface["NetworkInterfaceId"], region=region)
                arns[arn] = "network-interface"
        elif key == "rds_instance" and resources[key]:
            for instance in resource_data:
                rds_arn = instance["DBInstanceArn"]
                arns[rds_arn] = "rds_instance"
                subgrp = instance['DBSubnetGroup']['DBSubnetGroupName']
                subgrp_arn = gen_arn(account_id=account, resource_type="subgrp",
                                     resource_id=subgrp, region=region)
                arns[subgrp_arn] = "subgrp"
        elif key == "route_tables" and resources[key]:
            for rtb in resource_data:
                arn = gen_arn(account_id=account, resource_type="route-table",
                              resource_id=rtb["RouteTableId"], region=region)
                arns[arn] = "route-table"
        elif key == "s3_buckets" and resources[key]:
            for bucket in resource_data:
                arn = gen_arn(account_id=account, resource_id=bucket,
                              resource_type="s3")
                arns[arn] = "s3"
        elif key == "secrets" and resources[key]:
            for secret in resource_data:
                arn = secret["ARN"]
                arns[arn] = "secret"
        elif key == "security_groups" and resources[key]:
            for grp in resource_data:
                arn = gen_arn(account_id=account, resource_type="security-group",
                              resource_id=grp["GroupId"], region=region)
                arns[arn] = "security-group"
        elif key == "target_groups" and resources[key]:
            for grp in resource_data:
                arn = grp["TargetGroupArn"]
                arns[arn] = "elasticloadbalancing"
        elif key == "vpc" and resources[key]:
            for vpc in resource_data:
                arn = gen_arn(account_id=account, resource_type="vpc",
                              resource_id=vpc["VpcId"], region=region)
                arns[arn] = "vpc"
        elif key == "vpc_end_points" and resources[key]:
            for ep in resource_data:
                arn = gen_arn(account_id=account, resource_type="vpc-endpoints",
                              resource_id=ep["VpcEndpointId"], region=region)
                arns[arn] = "vpc-endpoints"
        elif key == "vpc_subnets" and resources[key]:
            for subnet in resource_data:
                arns[subnet["SubnetArn"]] = "subnet"

    # for arn in arns:
    #     print(arn, arns[arn])
    return arns


def validate(key, val):
    if not key or not val:
        logging.warning("Error: key and value must be specified")
        return 1
    # Not all the tags in aws are this restrictive, but we are aiming to comply
    # with all.
    if len(key) >= 128:
        logging.warning("Error: Key value too long. Must be <= 128")
        return 1
    if len(val) >= 256:
        logging.warning("Error: Key value too long. Must be <= 256")
        return 1
    pattern = r"[-a-zA-Z0-9+=._:@]+"
    if re.search(pattern, key).group() != key:
        logging.warning(f"Error: key invalid. Must match {pattern}")
        return 1
    if re.search(pattern, val).group() != val:
        logging.warning(f"Error: val invalid. Must match {pattern}")
        return 1
    return 0


def check_existing_tags(arns, key, value):
    """
    returns a dict containing arns which already have a given tag
    """
    diffs = {}
    tagging_client = boto3.client('resourcegroupstaggingapi')
    try:
        tag_filters = {'Key': key}
        resp = tagging_client.get_resources(TagFilters=[tag_filters])
        if len(resp['ResourceTagMappingList']) > 0:
            for resource in resp['ResourceTagMappingList']:
                arn = resource['ResourceARN']
                if arn in arns.keys():
                    for tag in resource["Tags"]:
                        if tag['Key'] == key and tag['Value'] != value:
                            diffs[arn] = {'old': tag["Value"], 'new': value}
    except:
        logging.warning("Error when attempting to check for existing tags")
    return diffs


# TODO: add "yes_to_all" option
# todo: look up how dryrun is handled elsewhere
def tag(arcade_name, key, value, dryrun=False, yes_to_all=False):
    """
    tag - coordinates and tags. Returns the arcade name if the arcade name is not found
    """
    if validate(key, value) != 0:
        return
    arns = get_arcade_resource_arns(arcade_name=arcade_name)
    # Passing grv manifest up the chain
    if arns == arcade_name:
        return arcade_name
    print(
        f"Found {len(arns)} resources to tag in {arcade_name}. Enable verbose mode to see them listed.")
    for arn in arns:
        logging.info(arn)
    if dryrun:
        return
    else:
        diffs = check_existing_tags(arns, key, value)
        if len(diffs) > 0:
            print(
                f"The tag operation will overwrite at least {len(diffs)} existing tags:")
            for arn in diffs:
                print(
                    f"{arn}, {key}:\n\told: {diffs[arn]['old']}\n\tnew: {diffs[arn]['new']}")
            if not yes_to_all:
                cont = input(
                    "Note that due to the way AWS handles tagging, there may be more tags that will be overwritten that what is shown here. Would you like to continue anyway? [y/n] ")
                if cont != 'y':
                    print("Aborting")
                    return
        else:
            if not yes_to_all:
                cont = input("Are you ready to tag? [y/n] ")
                if cont != 'y':
                    print("Aborting")
                    return

        tagging_client = boto3.client('resourcegroupstaggingapi')
        for arn in arns.keys():
            # handle non-standard cases first
            if arns[arn] == "hostedzone" or arns[arn] == "healthcheck":
                r53 = boto3.client('route53')
                res_id = arn.split("/")[-1]
                try:
                    resp = r53.change_tags_for_resource(ResourceType=arns[arn],
                                                        ResourceId=res_id, AddTags=[{'Key': key, 'Value': value}])
                    if resp['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logging.warn(f"Problem tagging {arn}")
                        logging.warn(f"HTTP Status Code {resp['ResponseMetadata']['HTTPStatusCode']}")
                except ClientError as err:
                    logging.warning(err.response)
                except Exception as e:
                    logging.warning(e.response)
                    logging.warning("Skipping")
            else:
                try:
                    resp = tagging_client.tag_resources(
                        ResourceARNList=[arn], Tags={key: value})
                    if resp['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logging.warn(f"Problem tagging {arn}")
                        logging.warn(f"HTTP Status Code {resp['ResponseMetadata']['HTTPStatusCode']}")
                    if not resp['FailedResourcesMap']:
                        logging.info(f"Tagged {arn}")
                    else:
                        logging.warning(f"Failed to tag {arn}")
                        logging.warning(
                            resp['FailedResourcesMap'][arn]['ErrorMessage'])
                except (ClientError, AttributeError) as err:
                    logging.warning(f"{arn} failed with error: {err}")
                    logging.warning(err.response)
                except Exception as e:
                    logging.warning(e.response)
                    logging.warning("Skipping")
        print("Done")
    return
