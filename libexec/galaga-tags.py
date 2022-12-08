#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-tags -- Print tags associated with a GALAGA to stdout.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1.5'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Print tags associated with a GALAGA/GSD to stdout."

import argparse

import boto3

from arclib import log, storage, common


def main():
    """
    %(prog)s - Print out the tags associated with an ASD.
    """
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade galaga tags')
    parser.add_argument("-p", "--path", required=True,
                        help="File you want to see the tags for")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    filename = args.path

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    s3_client = session.client('s3')
    response = s3_client.get_object_tagging(Bucket=bucket, Key=filename)
    for tag in response['TagSet']:
        print(f"{tag['Key']}={tag['Value']}")


if __name__ == "__main__":
    main()
