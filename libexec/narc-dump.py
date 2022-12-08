#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
narc-dump -- Display Hydrated Narc Configs to stdout
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Print hydrated Asteroid config to stdout, for a given ARCADE."


import logging
import boto3
import argparse
import os
import json
from pathlib import Path

from arclib import log, storage, common


def main():
    """
    %(prog)s - Display Hydrated Narc Configs to stdout
    """
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade narc dump')
    parser.add_argument("-A", "--arcade", help='Arcade Name')
    parser.add_argument("-b", "--bucket", help="Bucket of s3.")
    parser.add_argument("-p", "--path", help="Full path with filename in s3", required=True)
    parser.add_argument("-J", "--JSON", help="Display output in formatted json format", action="store_true")
    parser.add_argument("-s", "--save", help="Saves the JSON document to the (/usr/local/tmp) directory", action="store_true")

    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    session = boto3.session.Session()

    if args.arcade:
        arcade = args.arcade
    else:
        arcade = os.environ.get('ARCADE_NAME')

    if args.bucket:
        bucket = args.bucket

    if not args.bucket:
        bucket = storage.get_arcade_buckets(session, arcade)['infrastructure']

    display_file = storage.s3_json_to_dict(session, bucket, f"narc/{args.path}")

    if args.JSON:
        print(json.dumps(display_file, sort_keys=True, indent=4, default=str))
    else:
        print(json.dumps(display_file, default=str))
    if args.save:
        with open(f"{atmp}/{display_file['service']}.json", "w") as filedump:
            json.dump(display_file, filedump, indent=4)

        narc_file = Path(f"{atmp}/{display_file['service']}.json")

        if narc_file.is_file():
            print(f"{atmp}/{display_file['service']}.json has been downloaded")
        else:
            print(f"{atmp}/{display_file['service']}.json is not present.")


# TODO library: temp dir use happens everywhere, we should generalize in arclib
try:
    # will inherit from parent program (assuming `arcade`)
    if os.environ['ATMP']:
        atmp = os.environ['ATMP']
except Exception:
    # use something we know exists if running standalone
    atmp = '/tmp'


if __name__ == '__main__':
    main()
