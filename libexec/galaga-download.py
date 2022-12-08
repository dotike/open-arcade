#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
asteroid-download -- Download GALAGA JSON to local ATMP directory.
'''

# @depends: boto3, python (>=3.8)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Download GALAGA JSON to local ATMP directory."

import argparse
import json
import os
import sys

import boto3

from arclib import storage, log, common


def main():
    """
    %(prog)s - Download GALAGA JSON to ATMP dir
    """
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade galaga download')
    parser.add_argument("-p", "--path", help="Full path with filename in s3", required=True)
    parser.add_argument("-A", "--arcade", help='ARCADE name', required=False)
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    calling_script = os.path.splitext(os.path.basename(__file__))
    calling_action = calling_script[0].split('-')[1]

    if not args.arcade and calling_action == 'download':
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade", file=sys.stderr)
            sys.exit(1)
    arcade_name = args.arcade

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    tmp_dir = os.getenv("ATMP", '/tmp')
    galaga_file = f'{tmp_dir}/{arcade_name}.json'

    json_dict = storage.load_arcade_json_to_dict(bucket, args.path)
    if not json_dict:
        print(f"GALAGA file {args.path} does not exist in s3.")
        sys.exit(1)

    if calling_action == 'download':
        # We wanted the downloaded Galaga JSON to be ARCADE scoped.
        json_dict['name'] = arcade_name
        with open(galaga_file, 'w', encoding="utf-8") as json_file:
            json_file.write(json.dumps(json_dict,
                                       default=lambda o: o.__dict__,
                                       sort_keys=False,
                                       indent=4))
        print(f"Galaga {args.path} downloaded to {galaga_file}")

    print(json.dumps(json_dict,
                     default=lambda o: o.__dict__,
                     sort_keys=False,
                     indent=4))

    sys.exit(0)


if __name__ == '__main__':
    main()
