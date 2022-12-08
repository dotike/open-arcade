#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-add -- Add a service to a local Galaga json document.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Add a service to a local Galaga JSON document."

import argparse
from datetime import datetime
import json
import os
from pprint import pprint
import sys

import boto3

from arclib import common
from arclib import galaga
from arclib import log
from arclib import storage


def main():
    """
%(prog)s - Add a service to a local Galaga json document.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=main.__doc__,
        prog="arcade galaga add",
    )
    parser.add_argument("-A", "--arcade", help="Arcade name")
    parser.add_argument("-p", "--path", help="S3 path to the gsd service json file", required=True)
    parser.add_argument("-o", "--override", help="GSD service override key=value", action='append')
    parser.add_argument("--galaga-name", help="Set the 'name' field in the galaga file.", action='store')
    parser.add_argument("-s", "--silent", action="store_true", help="Silence all output")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)
    arcade_name = args.arcade
    os.environ["AWS_DEFAULT_REGION"] = common.get_arcade_region(arcade_name)

    tmp_dir = os.getenv("ATMP", '/tmp')

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    gsd_json = storage.load_arcade_json_to_dict(bucket, args.path)
    if gsd_json is None:
        print(f"Not able to access {args.path} in s3 bucket {bucket}")
        sys.exit(1)

    calling_script = os.path.splitext(os.path.basename(__file__))
    calling_action = calling_script[0].split('-')[1]

    if args.override:
        overrides = args.override
    else:
        overrides = []

    galaga_name = arcade_name
    if args.galaga_name:
        galaga_name = args.galaga_name
    galaga_file = f'{tmp_dir}/{galaga_name}.json'
    if os.path.exists(galaga_file):
        galaga_dict = storage.load_json_file_to_dict(galaga_file)
    else:
        print(f"Galaga file not found: {galaga_file}")
        sys.exit(1)

    if calling_action == 'remove':
        if overrides:
            galaga_component = galaga_dict
            for override in overrides:
                galaga_component = galaga.remove_override(galaga_component, gsd_json, override)
        else:
            galaga_component = galaga.remove_component(galaga_dict, gsd_json['name'], args.path)
    else:
        galaga_component = galaga.add_component(galaga_dict, gsd_json['name'], args.path)
        for override in overrides:
            galaga_component = galaga.add_override(galaga_component, gsd_json, override)

    galaga_component['createTime'] = datetime.utcnow().strftime("%Y/%m/%d/%H/%M")
    with open(galaga_file, 'w', encoding="utf-8") as json_file:
        json_file.write(json.dumps(galaga_component,
                                   default=lambda o: o.__dict__,
                                   sort_keys=False,
                                   indent=4))

    if not args.silent:
        pprint(galaga_component)
        print(f"Galaga {galaga_name} is modified under {galaga_file}")

    sys.exit(0)


if __name__ == "__main__":
    main()
