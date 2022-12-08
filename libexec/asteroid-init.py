#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
asteroid-init -- Uploads Asteroid json schema to S3 Bucket.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Initalizes an ARCADE to allow Asteroids to function."
__usage__ = """
The key purpose of this program is to upload the JSON schemas to the Asteroid Service Directory.. If there is a new
schema, then you can pass that in with `--schema`. If no schema is provided then the default schema
will be used.

Examples:
    
    $ arcade asteroid init --arcade tiny_sun.arc
    
    $ arcade asteroid init --arcade tiny_sun.arc --schema misc/asteroids/schema/asteroid-schema.json
"""

import boto3
import argparse
import json
import os

from arclib import storage, log, common


def main():
    """
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid init', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-s", "--schema", help="Local path to the JSON schema", default="misc/asteroids/schema/asteroid-schema.json")
    requiredNamed = parser.add_argument_group('required arguments')
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)
    
    if args.schema == "misc/asteroids/schema/asteroid-schema.json":
        schema_file = f"{os.environ['MYHIER']}/misc/asteroids/schema/asteroid-schema.json"
    else:
        schema_file = args.schema
    
    asteroid_schema_file_s3 = "asteroid-schema.json"

    with open(schema_file) as f:
        data = json.load(f)
        json_data = json.dumps(data, default=lambda o: o.__dict__, sort_keys=False, indent=4)
        storage.upload_to_s3_session(session, bucket, json_data, asteroid_schema_file_s3)


if __name__ == "__main__":
    main()
