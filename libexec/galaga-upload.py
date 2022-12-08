#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-upload -- Upload a completed GALAGA or GSD JSON document from the local machine to S3
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1.5'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Upload a completed GALAGA or GSD JSON document from the local machine to S3."
__usage__=""


import argparse
from datetime import datetime
import hashlib
import json
import logging
import os
from pprint import pprint
import sys

import boto3

from arclib import galaga, log, storage, common


def main():
    """
%(prog)s - Upload a completed Galaga json document from the local machine to S3
    """
    utcnow = datetime.utcnow()
    dateradix = utcnow.strftime("%Y/%m/%d/%H/%M")
    calling_script = os.path.splitext(os.path.basename(__file__))
    calling_type = calling_script[0].split('-')[0]

    # Start of parser
    parser = argparse.ArgumentParser(description=__description__,
                                     epilog=__usage__, prog='arcade galaga upload',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--file", help="GALAGA or GSD JSON to upload", required=True)
    parser.add_argument("-s", "--silent", action="store_true", help="Silence all output")
    parser.add_argument("-t", "--tag", help="Create alias with this tag name.")

    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    tmp_dir = os.getenv("ATMP", '/tmp')

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    if args.file:
        filename = args.file

    if not os.path.exists(filename):
        print(f"The Galaga json file {filename} does not exist")
        sys.exit(1)

    galaga_json = storage.read_file(filename)
    galaga_dict = json.loads(galaga_json)
    if not galaga.validate_galaga_json(galaga_dict, calling_type):
        print(f"{filename} is not valid json.")
        sys.exit(1)

    logging.info(f"uploading {filename}")

    hashjson = hashlib.md5(str(filename).encode('utf-8')).hexdigest()
    radixhash = f"{calling_type}/{galaga_dict['name']}/{galaga_dict['version']}/{dateradix}/{hashjson}.json"
    radixhash_latest = f"{calling_type}/{galaga_dict['name']}/latest/latest.json"
    tagline = f"original={radixhash}"
    logging.info(f" version upload path: {radixhash}")
    logging.info(f" latest upload path: {radixhash_latest}")

    current_version_galaga = storage.upload_to_s3(bucket, galaga_json, radixhash)
    if not current_version_galaga:
        logging.info(f" Version: {galaga_dict['version']} FAILED to upload to {bucket} {radixhash}")
        sys.exit(1)

    new_latest = storage.upload_to_s3(bucket, galaga_json, radixhash_latest)
    if not new_latest:
        logging.info(f" FAILED Uploading: latest on {bucket} {radixhash}")
        sys.exit(1)

    latest_tagged = storage.tag_s3_file(bucket, radixhash_latest, tagline)

    if args.tag:
        alias_key = f"{calling_type}/{galaga_dict['name']}/{args.tag}.json"
        alias_done = storage.upload_to_s3(bucket, galaga_json, alias_key)
        if not alias_done:
            logging.info(f" FAILED Uploading: {args.tag} on {bucket} {radixhash}")
            sys.exit(1)

        alias_tagged = storage.tag_s3_file(bucket, alias_key, tagline)

    if not args.silent:
        print(f"{bucket} {radixhash}")
        print(f"{bucket} {radixhash_latest}")
        if args.tag:
            print(f"{bucket} {alias_key}")


if __name__ == '__main__':
    main()
