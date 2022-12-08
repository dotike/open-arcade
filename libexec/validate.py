#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
validate -- compares the contents of an arcade inventory file to a freshly
pulled copy of the gravitar manifest. Largely a sanity check.
'''

# @depends: boto3, python (>=3.8)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "The validate tool compares an arcade inventory file to the gravitar manifest"
__usage__ = """
The validate tool is a pretty simple sanity check against the output of the inventory tool. It pulls a copy of the gravitar manifest for that arcade and then compares it to the contents of the inventory output.

Example Usage:

$ arcade inventory -A dry_sea.arc -o
Wrote inventory manifest to /Users/carlos.vazquez-chapa/tmp/arcade/dry_sea.arc-asteroid-inventory.json

$ arcade validate -f /Users/carlos.vazquez-chapa/tmp/arcade/dry_sea.arc-asteroid-inventory.json

Add -v for more detailed output.

"""

from datetime import datetime
import hashlib
import logging
import os
import sys
import argparse
import json
import boto3

from arclib.eks import list_eks
from arclib.grv import get_vpc_id
from arclib.k8s import load_arcade_k8s_config
from arclib.narc_k8s import get_all_services
from arclib import log, common


# --------------------------------------------------------------------
#
# main
#
# --------------------------------------------------------------------
def main():
    MIN_PYTHON = (3, 8)
    if sys.version_info < MIN_PYTHON:
        sys.exit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or later is required.\n")

    # tool_name = os.path.basename(__file__)
    # version = __version__

    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade validate',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-f', '--file', help='Arcade manifest')

    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if os.path.exists(args.file):
        with open(args.file, 'r') as fp:
            manifest_dict = json.load(fp)

        arcade_name = manifest_dict['arcade_name']
        ec2_data_raw = manifest_dict['ec2_instance']
        hosted_zone_rec = manifest_dict['hosted_zone_records']
        hosted_zone_id = manifest_dict["hosted_zone"]["Id"].replace("/hostedzone/", "")
        igw = manifest_dict['internet_gateways']
        vpc = manifest_dict['vpc']
        vpc_subnets = manifest_dict['vpc_subnets']
        # vpc_id          = manifest_dict['vpc_id']
        vpc_endpoints = manifest_dict["vpc_end_points"]
        route_tables = manifest_dict['route_tables']
        network_acl = manifest_dict['network_acl']
        security_grps = manifest_dict['security_groups']

        grv_manifest = get_grv_manifest(arcade_name=arcade_name)
        ec2_data = []
        for val in ec2_data_raw:
            ec2_data.append(val['Instances'][0])

        hosted_zone_rec.sort(key=hz_sort)  # risky; name not unique
        grv_hosted_zone_rec = list(grv_manifest['route53']['names'])
        grv_hosted_zone_rec.sort(key=hz_sort)
        vpc_subnets.sort(key=vpc_sort)
        route_tables.sort(key=rt_sort)
        security_grps.sort(key=sec_grp_sort)
        grv_security_grps = list(
            grv_manifest["security_groups"].values())
        grv_security_grps.sort(key=sec_grp_sort)

        common_check([grv_manifest],
                     [manifest_dict['gravitar_manifest']], "Gravitar Manifest")
        common_check(list(grv_manifest["instances"].values()), ec2_data,
                     "EC2 Instance", id_key="InstanceId")
        individual_compare(grv_manifest["route53"]["zone_id"],
                           hosted_zone_id, "Hosted Zone ID")
        common_check(grv_hosted_zone_rec, hosted_zone_rec,
                     "Hosted Zone (Route 53) Records", id_key="Name")  # risky; name not unique
        common_check(list(grv_manifest["igw"].values()), igw,
                     "Internet Gateway", id_key="InternetGatewayId")
        common_check(list(grv_manifest["network_acls"].values()),
                     network_acl, "Network ACL", id_key="NetworkAclId")
        common_check(list(grv_manifest["route_tables"].values()),
                     route_tables, "Route Tables", id_key="RouteTableId")
        common_check(grv_security_grps, security_grps,
                     "Security Groups", id_key="GroupId")
        common_check(list(grv_manifest["vpc"].values()), vpc, "VPC",
                     id_key="VpcId")
        common_check(list(grv_manifest["subnets"].values()),
                     vpc_subnets, "VPC Subnet", id_key="SubnetId")
        common_check(list(grv_manifest["vpc_endpoints"].values()),
                     vpc_endpoints, "VPC Endpoints", id_key="VpcEndpointId")

        print("Starting Layer Check".center(60, "-"))
        layers = report_layers(arcade_name=arcade_name)
        for key, val in layers.items():
            print(f"{key}: {val}")
        print("Layer Check Done".center(60, "-"))

    else:
        print(f"\n\nERROR: {args.file} not found. Try again.\n\n")
        sys.exit(1)

    sys.exit(0)
    # End of main


# ---------------------------------------------------------
#
# get_grv_manifest - simplified version copied from inventory.py
#
# ---------------------------------------------------------
def get_grv_manifest(arcade_name):
    s3_name = arcade_name.replace('.arc', '')
    s3_name = s3_name.replace('_', '')

    bucket_name = ""
    gravitar_manifest = ""
    manifest_found = False

    s3_client = boto3.client('s3')
    s3_resource = boto3.resource('s3')
    response = s3_client.list_buckets()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        buckets = response['Buckets']
        for entry in buckets:
            if s3_name in entry['Name']:
                if 'infrastructure' in entry['Name']:
                    bucket_name = entry['Name']
                    manifest_found = True
                    break
                # End of if
            # End of if
        # End of for

    if manifest_found:
        bucket = s3_resource.Bucket(bucket_name)
        for obj in bucket.objects.all():
            key = obj.key
            if 'gravitar' in key:
                body = obj.get()['Body'].read()
                gravitar_manifest = json.loads(body.decode("utf-8"))
                break
                # End of if
            # End of for
        # End of if

    if len(gravitar_manifest) <= 0:
        logging.error("ERROR: gravitar manifest not found !")

    return gravitar_manifest
    # End of get_grv_mainfest


ignored_tags = [
    "TagSane",
    "AvailableIpAddressCount"
]

time_tags = [
    "AttachTime",
    "CreationTimestamp",
    "LaunchTime",
    "UsageOperationUpdateTime"
]


# --------------------------------------------------------------------
#
# recurisve_compare is the primary comparison loop this tool uses
#
# --------------------------------------------------------------------
def recursive_compare(dict1, dict2, dict1_name, dict2_name):
    for key in dict1:
        if key in ignored_tags:
            logging.info("Mismatch caused by ignored key: %s", key)
            continue
        if key not in dict2.keys():
            logging.warning("   %s exists in %s but not in %s", key,
                            dict1_name, dict2_name)
            continue
        if isinstance(dict1[key], dict):
            recursive_compare(dict1[key], dict2[key], dict1_name,
                              dict2_name)
        elif isinstance(dict1[key], list):
            for i in range(len(dict1[key])):
                if isinstance(dict1[key][i], dict):
                    recursive_compare(dict1[key][i], dict2[key][i],
                                      dict1_name, dict2_name)
        elif dict1[key] != dict2[key] and key not in ignored_tags:
            if key in time_tags and equivalent_time(dict1[key],
                                                    dict2[key]):
                logging.info("%s and %s have differing time formats",
                             dict1_name, dict2_name)
                continue
            logging.warning("  Mismatch Detected in %s", key)
            logging.info(" %s: %s\n\t   %s: %s", dict1_name, dict1[key],
                         dict2_name, dict2[key])
    return


# --------------------------------------------------------------------
#
# hash_compare - returns true if they are the same, false otherwise
#
# --------------------------------------------------------------------
def hash_compare(dict1, dict2):
    h1 = hashlib.md5(json.dumps(dict1).encode('utf-8'))
    h2 = hashlib.md5(json.dumps(dict2).encode('utf-8'))
    if h1.hexdigest() == h2.hexdigest():
        return True
    else:
        return False


# --------------------------------------------------------------------
#
# common_check is used to check several things that should be identical
#
# --------------------------------------------------------------------
def common_check(recent_list, old_list, check_type,
                 recent_name="Gravitar Manifest", old_name="File Copy",
                 id_key=""):
    print((f"Starting {check_type} Check").center(60, "-"))

    if len(recent_list) > len(old_list):
        logging.warning(("%s has more entries than %s."
                         "ONLY CHECKING THE ONES IN COMMON"), recent_name, old_name)
    elif len(recent_list) < len(old_list):
        logging.warning(("%s has fewer entries than %s. "
                         "ONLY CHECKING THE ONES IN COMMON"), recent_name, old_name)

    if id_key != "" and len(get_exclusive_ids(recent_list, old_list,
                                              id_key)) > 0:
        logging.info("ID's unique to %s:", recent_name)
        for my_id in get_exclusive_ids(recent_list, old_list, id_key):
            logging.info("\t%s", my_id)
    if id_key != "" and len(get_exclusive_ids(old_list, recent_list,
                                              id_key)) > 0:
        logging.info("ID's unique to %s:", old_name)
        for my_id in get_exclusive_ids(old_list, recent_list, id_key):
            logging.info("\t%s", my_id)

    # TODO: Clean this up
    if id_key == "":  # order-based if no id is given
        for i in range(len(recent_list)):
            if not hash_compare(recent_list[i], old_list[i]):
                logging.info("Mismatch arose during %s Check",
                             check_type)  # info because not necessarily a bad thing
                if id_key in recent_list[i]:
                    logging.info("See %s", id_key)
                recursive_compare(recent_list[i], old_list[i],
                                  recent_name, old_name)
    else:  # id based when possible
        ids = get_shared_ids(recent_list, old_list, id_key)
        for my_id in ids:
            recent_entry = get_dict_by_id(recent_list, id_key, my_id)
            old_entry = get_dict_by_id(old_list, id_key, my_id)
            if not hash_compare(recent_entry, old_entry):
                logging.info("Mismatch arose during %s Check",
                             check_type)
                if id_key in recent_entry:
                    logging.info("See %s", my_id)
                recursive_compare(recent_entry, old_entry, recent_name,
                                  old_name)
    print((f"{check_type} Check Completed").center(60, "-"))
    return


# --------------------------------------------------------------------
#
# individual_compare wraps some logging around simple comparison
#
# --------------------------------------------------------------------
def individual_compare(recent_item, old_item, check_type,
                       recent_name="Gravitar Manifest",
                       old_name="File Copy"):
    print((f"Starting {check_type} Check").center(60, "-"))
    if recent_item != old_item:
        logging.warning("Mismatch Detected")
        logging.warning(" %s: %s\n\t   %s: %s", recent_name, recent_item,
                        old_name, old_item)
    print((f"{check_type} Check Completed").center(60, "-"))
    return


# --------------------------------------------------------------------
#
# list_ids lists the ids contained in a list of dicts where the key
# for the id is `id_key`
#
# --------------------------------------------------------------------
def list_ids(list_to_check, id_key):
    ids = []
    for dictionary in list_to_check:
        if id_key in dictionary.keys():
            ids.append(dictionary[id_key])
    return ids


# --------------------------------------------------------------------
#
# get_shared_ids
#
# --------------------------------------------------------------------
def get_shared_ids(list1, list2, id_key):
    list1_ids = list_ids(list1, id_key)
    list2_ids = list_ids(list2, id_key)
    return list(set(list1_ids).intersection(set(list2_ids)))


# --------------------------------------------------------------------
#
# get_exclusive_ids
#
# --------------------------------------------------------------------
def get_exclusive_ids(list1, list2, id_key):
    list1_ids = list_ids(list1, id_key)
    list2_ids = list_ids(list2, id_key)
    return list(set(list1_ids).difference(set(list2_ids)))


# --------------------------------------------------------------------
#
# get_dict_by_id
#
# --------------------------------------------------------------------
def get_dict_by_id(list_to_read, id_key, my_id):
    # is this optimal? Probably not. Does it need to be? Probably not
    for dictionary in list_to_read:
        if id_key in dictionary.keys() and dictionary[id_key] == my_id:
            return dictionary
    return {}


# --------------------------------------------------------------------
#
# equivalent_time is needed because there are a few different time
# formats floating around
#
# --------------------------------------------------------------------
def equivalent_time(str1, str2):
    dt1 = datetime.fromisoformat('2001-01-02')
    dt2 = datetime.fromisoformat('2001-01-01')
    formats = [
        "%Y-%m-%d %H:%M:%S%z",
        "%d-%b-%Y %H:%M:%S",
        "%d-%B-%Y %H:%M:%S"
    ]
    for fmt in formats:
        try:
            dt1 = datetime.strptime(str1, fmt)
            dt1 = dt1.replace(tzinfo=None)
        except ValueError:
            pass
    for fmt in formats:
        try:  # needs to be like this in case dt1 excepts before it could
            # reach dt2
            dt2 = datetime.strptime(str2, fmt)
            dt2 = dt2.replace(tzinfo=None)
        except ValueError:
            pass
    if dt1 == dt2:
        return True
    else:
        return False


# --------------------------------------------------------------------
#
# vpc_sort
#
# --------------------------------------------------------------------
def vpc_sort(e):
    return e["SubnetId"]


# --------------------------------------------------------------------
#
# rt_sort
#
# --------------------------------------------------------------------
def rt_sort(e):
    return e["RouteTableId"]


# --------------------------------------------------------------------
#
# sec_grp_sort
#
# --------------------------------------------------------------------
def sec_grp_sort(e):
    return e["GroupId"]


# --------------------------------------------------------------------
#
# hz_sort
#
# --------------------------------------------------------------------
def hz_sort(e):
    return e["Name"]


# --------------------------------------------------------------------
#
# report_layers returns a dict indicating whether or not a given layer
# is in place or not.
#
# --------------------------------------------------------------------
def report_layers(arcade_name):
    r_dict = {}

    r_dict["Gravitar (VPC)"] = "NOT READY"
    r_dict["Galaga (EKS)"] = "NOT READY"
    r_dict["Asteroids"] = "NOT ALL ACTIVE"

    asteroid_stats = get_asteroid_stats(arcade_name)

    if get_vpc_id(arcade_name):
        r_dict["Gravitar (VPC)"] = "READY"
    if list_eks(arcade_name):
        r_dict["Galaga (EKS)"] = "READY"
    if len(asteroid_stats) > 0 and "PENDING" not in asteroid_stats.values():
        r_dict["Asteroids"] = "ALL ACTIVE"
    elif len(asteroid_stats) == 0:
        r_dict["Asteroids"] = "NONE ACTIVE"
    else:
        for ast, stat in asteroid_stats.items():
            if stat != "ACTIVE":
                logging.info("Asteroid %s: %s", ast, stat)

    return r_dict


# --------------------------------------------------------------------
#
# copied and modified from asteroid-list
#
# --------------------------------------------------------------------
def get_asteroid_stats(arcade):
    asteroids = {}
    try:
        load_arcade_k8s_config(arcade)
        all_narc_deployments = get_all_services()

        for deployment in all_narc_deployments:
            narc_id = deployment.metadata.name
            status = ""
            if deployment.status.available_replicas == deployment.status.replicas:
                status = "ACTIVE"
            else:
                status = "PENDING"

            asteroids[narc_id] = status
    except:
        pass
    return asteroids


# --------------------------------------------------------------------
#
# Entry point
#
# --------------------------------------------------------------------
if __name__ == '__main__':
    main()
    # End of entry point
