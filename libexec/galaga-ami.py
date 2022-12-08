#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-ami --
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""


import boto3
import json
import os
import sys
import argparse
import logging
import time
from pprint import pprint
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError

from arclib import grv, storage, log, common, ami


def main():
    """Main function of the cli."""
    parser = argparse.ArgumentParser(description='GALAGA AMI Utility', prog='arcade galaga ami',)
    subparsers = parser.add_subparsers(dest='subcommand')

    p_export = subparsers.add_parser("export", help="Export AMI to account S3 bucket")
    p_export.add_argument("-a", "--imageid", help="AMI ImageId", required=True)

    p_import = subparsers.add_parser("import", help="Import VMDK image from account S3 bucket")
    p_import.add_argument("-n", "--name", help="Image name in S3", required=True)
    p_import.add_argument("-c", "--copy", help="Copy AMI accross all regions after import", action='store_true')

    p_copy = subparsers.add_parser("copy", help="Copy AMI across all regions")
    p_copy.add_argument("-i", "--imageid", help="AMI ImageId", required=True)

    p_describe = subparsers.add_parser("describe", help="Describe an AMI")
    p_describe.add_argument("-a", "--imageid", help="AMI ImageId", required=True)
    p_describe.add_argument("-j", "--json", help="JSON format", action='store_true')
    p_describe.add_argument("-J", "--JSON", help="Pretty JSON format", action='store_true')

    p_list = subparsers.add_parser("list", help="List of AMIs or images")
    p_list.add_argument("-s", "--s3", help="list of Images in S3", action='store_true')
    p_list.add_argument("-j", "--json", help="JSON format list of AMIs", action='store_true')
    p_list.add_argument("-J", "--JSON", help="Pretty JSON format list of AMIs", action='store_true')

    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    account_id = common.get_account_id()

    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)
    # bucket_name = "asd-1232114"

    default_path = 'images/'

    region_list = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']

    arcade_vmimport_role = ami.get_vmimport_role(session, bucket_name)

    if args.subcommand == 'list':
        if args.s3:
            header = 'NAME PATH SIZE'
            list = ami.list_images_in_s3(session, bucket_name, default_path)
        else:
            header = 'NAME ID CREATIONDATE'
            list = ami.list_amis(session)
        if args.json:
            print(json.dumps(list, default=str))
        elif args.JSON:
            print(json.dumps(list, indent=4, default=str))
        else:
            print(header)
            for ami_described in list:
                if args.s3:
                    print(f"{repr(ami_described['Name'])} {ami_described['Path']} {ami_described['Size']}")
                else:
                    print(f"{repr(ami_described['Name'])} {ami_described['ImageId']} {ami_described['CreationDate']}")
        sys.exit(0)

    elif args.subcommand == 'describe':
        ami_info = ami.ami_info(session, args.imageid)
        if args.json:
            print(json.dumps(ami_info, default=str))
        elif args.JSON:
            print(json.dumps(ami_info, indent=4, default=str))
        else:
            pprint(ami_info)
        sys.exit(0)

    elif args.subcommand == 'export':
        ami.export_ami(session, args.imageid, bucket_name, default_path, arcade_vmimport_role)
        sys.exit(0)

    elif args.subcommand == 'import':
        image_id = ami.import_image(session, args.name, bucket_name, default_path, arcade_vmimport_role)
        if args.copy:
            ami.wait_for_ami_availability(session, image_id)
            ami.copy_ami(session, image_id, region_list)
        sys.exit(0)

    elif args.subcommand == 'copy':
        ami.wait_for_ami_availability(session, args.imageid)
        ami.copy_ami(session, args.imageid, region_list)
        sys.exit(0)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
