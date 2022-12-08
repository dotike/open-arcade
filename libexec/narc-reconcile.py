#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
narc-reconcile -- Reconcile kubernetes vs S3 bucket.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Starts, stops, and modifies running services to match hydrated configuration in an ARCADE."


import asyncio
import boto3
import argparse
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import os
import sys
from arclib import narc_k8s as narc_k8s
from arclib import narc_ingress as narc_ingress
from arclib import narc_rds as narc_rds

from arclib.eks import get_eks_clusters_detail

from arclib import storage, log, common, k8s

from arclib.s3_object_lock import S3ObjectLock
from pprint import pprint


def clean_list(list, character, prefix=True):
    """Split the strings in the list to remove a part from each string.

    :param list: The list to work with
    :param character: The character to split each string on
    :param prefix: Is the prefix being trimmed away?
    :return: list of pruned strings
    """
    if prefix:
        part = 1
    else:
        part = 0
    cleanlist = []
    for i in list:
        cleanlist.append(i.split(character, 1)[part])
    return cleanlist


def deployment_list(appsv1, prefix):
    try:
        ret = appsv1.list_deployment_for_all_namespaces(watch=False)
    except ApiException as e:
        logging.error('k8s error: {}'.format(e))
        sys.exit(1)

    deployments = []
    for i in ret.items:
        logging.info("%s\t%s\t%s" %
                     (i.spec.replicas, i.metadata.namespace, i.metadata.name))
        if prefix in i.metadata.name:
            deployments.append(i.metadata.name)
    return deployments


def find_object(s3_client, bucket, prefix):
    """Find object from S3 bucket.

    :param s3_client: S3 client to work with
    :param bucket: Bucket to get object from
    :param prefix: search prefix
    :return: list of Objects
    """
    try:
        response = s3_client.list_objects(Bucket=bucket, Prefix=prefix)
    except ClientError as e:
        logging.error('AWS error: {}'.format(e))
        sys.exit(1)
    except NoCredentialsError as crede:
        logging.error('AWS error: {}'.format(crede))
        sys.exit(1)

    logging.info(response.get('Contents'))
    foundkeys = []
    for content in response.get('Contents', []):
        # yield content.get('Key')
        foundkeys.append(content.get('Key'))
    logging.info(foundkeys)
    return foundkeys


def find_ordered(session, bucket, filename):
    asddata = storage.s3_json_to_dict(session, bucket, filename)

    order = 0

    if 'order' in asddata:
        order = asddata['order']

    return order


async def create_narc(args, narcid, session, bucket, filename):
    asddata = storage.s3_json_to_dict(session, bucket, filename)
    if args.verbose:
        print(f'Creating: {narcid}')

    if asddata['component_type'] == 'k8s':
        return_code = await narc_k8s.executek8s_parallel(arcade_name=args.arcade, asddata=asddata)

        if return_code and (asddata["service_options"]["load_balanced"]["public"] or
                            asddata["service_options"]["load_balanced"]["private"]):

            lbcreated = narc_ingress.create_asteroid_ingress(arcade_name=args.arcade, asd_data=asddata)

            if not lbcreated:
                print(f'LB not created for {narcid}')

    elif asddata['component_type'] == 'rds':
        await narc_rds.create_rds_instance_parallel(arcade_name=args.arcade, asd_data=asddata)

    else:
        logging.error(f"Service type {asddata['component_type']} invalid for create")


def create_narc_serial(args, narcid, session, bucket, filename):
    asddata = storage.s3_json_to_dict(session, bucket, filename)
    if args.verbose:
        print(f'Creating: {narcid}')

    if asddata['component_type'] == 'k8s':
        return_code = narc_k8s.executek8s_serial(arcade_name=args.arcade, asddata=asddata)

        if return_code and (asddata["service_options"]["load_balanced"]["public"] or
                            asddata["service_options"]["load_balanced"]["private"]):

            lbcreated = narc_ingress.create_asteroid_ingress(arcade_name=args.arcade, asd_data=asddata)

            if not lbcreated:
                print(f'LB not created for {narcid}')

    elif asddata['component_type'] == 'rds':
        narc_rds.create_rds_instance_serial(arcade_name=args.arcade, asd_data=asddata)

    else:
        logging.error(f"Service type {asddata['component_type']} invalid for create")


async def restart_narc(args, narcid, service_type, session, bucket, filename):
    """
    For every running narc service (service not about to be created or deleted) we will look for the field
    'desired_state' to determine whether or not it is set to 'restart'.  If it is, a restart will be performed.
    Args:
        args:
        narcid:
        service_type:
        session:
        bucket:
        filename:

    Returns:

    """
    asddata = storage.s3_json_to_dict(session, bucket, filename)

    if service_type == "k8s":
        await narc_k8s.restartk8s_parallel(arcade_name=args.arcade, asddata=asddata, narcid=narcid)


async def modify_narc(args, narcid, service_type, session, bucket, filename):
    """
    For every running narc service (service not about to be created) we will schedule to check for modification
    Args:
        args:
        narcid:
        service_type:

    Returns:

    """
    if args.verbose:
        print(f'Checking {narcid} for modification')

    asddata = storage.s3_json_to_dict(session, bucket, filename)

    if asddata != {}:
        if service_type == "k8s":
            await narc_k8s.modifyk8s_parallel(arcade_name=args.arcade, asddata=asddata)
    else:
        print(f"No ASD found for NarcID: {narcid}")


async def delete_narc(args, narcid, service_type):
    if args.verbose:
        print(f'Destroying: {narcid}')

    if service_type == "k8s":
        await narc_k8s.nukeK8s_parallel(narcid)
        narc_ingress.delete_ingress(arcade_name=args.arcade, narc_id=narcid)

    # NOTE: WE ARE DELIBERATELY NOT REMOVING RDS DATABASES
    elif service_type == "rds":
        pass
    #    await narc_rds.delete_rds_resource_parallel(args.arcade, narcid)

    else:
        logging.error(f"Service type ({service_type}) invalid for delete")


async def main():
    """%(prog)s - Reconcile kubernetes vs S3 bucket."""
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade narc reconcile')
    parser.add_argument("-A", "--arcade", help="Arcade name")
    parser.add_argument("--dryrun", help="dry run", action="store_true")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', '')

    if not args.arcade:
        print("Arcade name is required.")
        sys.exit(1)

    eks_stat = get_eks_clusters_detail(arcade_name=args.arcade)
    if not eks_stat:
        print("No response when checking EKS status. Please ensure Galaga is correctly configured (see 'arcade galaga run')")
        exit(1)

    session = common.setup_arcade_session(args.arcade)
    k8s.load_arcade_k8s_config(args.arcade)
    s3_resource = session.resource('s3')
    s3_client = session.client("s3")
    appsv1 = client.AppsV1Api()

    buckets = storage.get_arcade_buckets(session, args.arcade)


    if 'infrastructure' not in buckets:
        print("Invalid arcade name or arcade bucket does not exist")
        sys.exit(1)

    lockfile_name = "reconcile.lock"

    with S3ObjectLock(buckets['infrastructure'], "Arcade", lockfile_name, args.verbose):
        narcdeployments = deployment_list(appsv1, 'narc')
        narcdeploymentsclean = clean_list(narcdeployments, '-')
        rds_status = narc_rds.get_rds_instances()
        narcasds = find_object(s3_client, buckets['infrastructure'], 'narc')
        narcasdsclean = clean_list(clean_list(narcasds, '/'), '.', False)
        rds_delete_list = set(rds_status) - set(narcasdsclean)
        deletelist = set(narcdeploymentsclean) - set(narcasdsclean)
        # gotta take into account running rds instances

        createlist = set(narcasdsclean) - set(narcdeploymentsclean) - set(rds_status)

        restartlist = set(narcasdsclean) - set(createlist) - set(deletelist) - set(rds_status)
        modifylist = set(narcasdsclean) - set(createlist) - set(deletelist) - set(rds_status) # TODO: handle RDS mod

        if args.dryrun or args.verbose > 0:
            print(f'narcdeployments: {narcdeployments}')
            print(f'narcdeploymentsclean: {narcdeploymentsclean}')
            print(f'rds_status: {rds_status}')
            print(f'narcasds: {narcasds}')
            print(f'narcasdsclean: {narcasdsclean}')
            pprint(f'delete list: {deletelist}')
            pprint(f'rds delete list: {rds_delete_list}')
            pprint(f'create list: {createlist}')
            pprint(f'modify list: {modifylist}')

        if not args.dryrun:

            # RESTART ###################################################################################
            restart_list = []
            for narcid in restartlist:
                filename = f'narc/{narcid}.json'

                restart_list.append(restart_narc(args, narcid, "k8s", session, buckets['infrastructure'], filename))

            return_codes = await asyncio.gather(*[x for x in restart_list])

            # MODIFY ####################################################################################
            # TODO: Handle RDS narc services as well. For now we attempt to skip them
            modify_list = []
            for narcid in modifylist:
                adjusted_narcid = f'narc-{narcid}'
                filename = f'narc/{narcid}.json'
                modify_list.append(modify_narc(args, adjusted_narcid, "k8s", session, buckets['infrastructure'], filename))

            return_codes = await asyncio.gather(*[x for x in modify_list])

            # DELETE ####################################################################################
            delete_list = []
            for narcid in deletelist:
                adjusted_narcid = f'narc-{narcid}'
                delete_list.append(delete_narc(args, adjusted_narcid, "k8s"))

            for narcid in rds_delete_list:
                adjusted_narcid = f'narc-{narcid}'
                delete_list.append(delete_narc(args, adjusted_narcid, "rds"))

            return_codes = await asyncio.gather(*[x for x in delete_list])

            # CREATE ####################################################################################
            create_list = []
            ordered_create_dict = {}
            for narcid in createlist:
                filename = f'narc/{narcid}.json'

                # Intercept any services with ordering attributes and make separate list
                # Does it matter if all asteroids are listed together as individual services???
                order = find_ordered(session, buckets['infrastructure'], filename)

                # Separate out ordered narc services from those that will be executed in parallel
                if order > 0:
                    if order in ordered_create_dict:
                        ordered_create_dict[order].append(narcid)
                    else:
                        ordered_create_dict[order] = [narcid]
                else:
                    create_list.append(create_narc(args, narcid, session, buckets['infrastructure'], filename))

            return_codes = await asyncio.gather(*[x for x in create_list])

            # Execute ordered narc services in order after all parallel services have already been created
            for order_index in sorted(ordered_create_dict):
                for narcid in ordered_create_dict[order_index]:
                    print(f"ORDER INDEX: {order_index}")
                    print(f"STARTING SERVICE: {narcid}")
                    filename = f'narc/{narcid}.json'
                    create_narc_serial(args, narcid, session, buckets['infrastructure'], filename)


if __name__ == "__main__":
    asyncio.run(main())
