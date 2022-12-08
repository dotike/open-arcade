#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
asd-init -- Initalize Asteroid Service Directory in an account.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Initalize Asteroid Service Directory in an account."

import boto3
import argparse
import json
import os

from arclib import storage, log, common


def main():
    """
    %(prog)s  Uploads Asteroid Service Directory json schema to S3 Bucket.
    """
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade asd init')
    parser.add_argument("-s", "--schema",
                        help="schema file to upload.",
                        default="asdschema.json")
    parser.add_argument("-b", "--bucket",
                        help="Bucket to upload to")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if args.schema == "asdschema.json":
        schema_file = f"{os.environ['MYHIER']}/misc/asteroids/schema/asdschema.json"
    else:
        schema_file = args.schema

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    if args.bucket:
        bucket = args.bucket

    with open(schema_file) as f:
        data = json.load(f)
        json_data = json.dumps(data, default=lambda o: o.__dict__, sort_keys=False, indent=4)
        storage.upload_to_s3_session(session, bucket, json_data, os.path.basename(schema_file))


if __name__ == "__main__":
    main()
