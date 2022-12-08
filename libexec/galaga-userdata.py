#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-userdata - manage ASG userdata
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Andy Dunlap <andy.dunlap.temp@addepar.com>'
__description__ = "Manage ASG userdata."

import argparse
import os
import sys
import logging
from pprint import pprint
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError

from arclib import ami
from arclib import common
from arclib import grv
from arclib import log
from arclib import storage


def main():
    """Main function of the cli."""
    parser = argparse.ArgumentParser(description='GALAGA userdata Utility', prog='arcade galaga userdata')
    subparsers = parser.add_subparsers(dest='subcommand')

    parser.add_argument("-A", "--arcade", help="ARCADE to work on")

    p_download = subparsers.add_parser("download", help="Download userdata from S3")
    p_download.add_argument("-p", "--path", help="S3 userdata file", required=True)

    p_upload = subparsers.add_parser("upload", help="Upload userdata file into S3")
    p_upload.add_argument("-g", "--gsd", help="GSD associated to this userdata", required=True)
    p_upload.add_argument("-f", "--file", help="Userdata file to upload", required=True)

    p_describe = subparsers.add_parser("cat", help="show a S3 userdata file")
    p_describe.add_argument("-p", "--path", help="Userdate file to cat from S3", required=True)

    p_list = subparsers.add_parser("list", help="List userdata files in S3")
    p_list.add_argument("-s", "--s3", help="list of Images in S3", action='store_true')
    p_list.add_argument("-j", "--json", help="JSON format list of AMIs", action='store_true')
    p_list.add_argument("-J", "--JSON", help="Pretty JSON format list of AMIs", action='store_true')

    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    # if not args.arcade:
    #     args.arcade = os.getenv('ARCADE_NAME')
    #     if not args.arcade:
    #         print("Arcade name missing, use --arcade")
    #         sys.exit(1)

    session = boto3.session.Session()
    # bucket_name = storage.get_arcade_buckets(session, args.arcade)['infrastructure']
    bucket_name = storage.get_account_global_bucket(session)
    tmp_dir = os.getenv("ATMP", '/tmp')
    default_path = 'userdata'

    if args.subcommand == 'list':
        key_list = storage.find_s3_keys(session, bucket_name, default_path)
        for item in key_list:
            print(item)
        sys.exit(0)

    elif args.subcommand == 'cat':
        key = args.path
        tmp_file = f"{tmp_dir}/{os.path.basename(args.path)}"
        storage.download_s3_file(session, bucket_name, key, tmp_file)
        with open(tmp_file, 'r') as file_buffer:
            userdata = file_buffer.read()
        print(userdata)
        sys.exit(0)

    elif args.subcommand == 'download':
        key = args.path
        filename = os.path.basename(args.path)
        storage.download_s3_file(session, bucket_name, key, filename)
        sys.exit(0)

    elif args.subcommand == 'upload':
        if storage.find_s3_keys(session, bucket_name, f"gsd/{args.gsd}/"):
            key = f"{default_path}/{args.gsd}/{os.path.basename(args.file)}"
            storage.upload_s3_file(session, bucket_name, key, args.file)
        sys.exit(0)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
