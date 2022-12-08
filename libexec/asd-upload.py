#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
asd-upload -- Upload a Service Description json file to the ASD.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Upload a Service Description json file to the ASD."

import argparse
import boto3
import json
import os
import sys
import logging

from jsonschema import validate
from jsonschema.exceptions import ValidationError, SchemaError

from arclib import storage, log, common


def main():
    """
    %(prog)s - Validate JSON file then upload to S3 bucket."""
    calling_script = os.path.splitext(os.path.basename(__file__))
    calling_type = calling_script[0].split('-')[0]
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade asd upload', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--file",
                        help="Location of the file to upload.  Use stdin if not given",
                        default="stdin")
    ## TODO: (TVB) Reading from stdin doesn't seem helpful at all here. Is this ever used?
    parser.add_argument("-b", "--bucket",
                        help="Bucket to upload to"),
    parser.add_argument("-t", "--tag", action="store", default="",
                        help="Create an alias with this tag name.\n(i.e.: 'raw_egg/asteroid-name/service-name' => 'asd/raw_egg/asteroid-name/service-name.json')")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Silence all output")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    session = boto3.session.Session()
    if args.bucket:
        bucket = args.bucket
    else:
        bucket = storage.get_account_global_bucket(session)

    filename = args.file

    if not os.path.exists(filename):
        print(f"The ASD json file {filename} does not exist", file=sys.stdout)
        sys.exit(1)

    asd_json = storage.read_file(filename)
    asd_dict = json.loads(asd_json)
    schema = storage.s3_json_to_dict(session, bucket, 'asdschema.json')
    try:
        validate(instance=asd_dict, schema=schema)
    except (ValidationError, SchemaError) as error:
        logging.error("JSON validation error: {}".format(error))
        sys.exit(1)

    logging.info(f"uploading {filename}")

    s3path = storage.upload_asteroid_json(session, bucket, 'asd',
                                          asd_dict['service'], asd_dict['version'],
                                          json.dumps(asd_dict, sort_keys=False, indent=4),
                                          silent=args.silent,
                                          tagpath=args.tag)
    if not s3path:
        sys.exit(1)


if __name__ == "__main__":
    main()
