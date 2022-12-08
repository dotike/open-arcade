#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Print tags associated with an asteroid or ASD to stdout."
__usage__ = """
Prints the tags associated with a given asteroid or ASD to stdout. 
These tags are generated when `arcade asteroid alias` is run. 

Example Usage:

    $ arcade asteroid show-tags -p asd/nginxwoof/test.json 

"""

import sys

import argparse
import boto3

from arclib import storage, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """

    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid show-tags', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-p", "--path",
                        help="Path to the file in S3")
    parser.add_argument("-b", "--bucket",
                        help="Target bucket containing file.")

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.path:
        print("S3 path (--path) is required", file=sys.stdout)
        sys.exit(1)

    filename = args.path
    session = boto3.session.Session()

    bucket = storage.get_account_global_bucket(session)

    if args.bucket:
        bucket = args.bucket

    s3_client = session.client('s3')
    response = s3_client.get_object_tagging(Bucket=bucket, Key=filename)
    for tag in response['TagSet']:
        print('{}={}'.format(tag['Key'], tag['Value']))
    sys.exit(0)


if __name__ == "__main__":
    main()
