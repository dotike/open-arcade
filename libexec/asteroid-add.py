#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Adds Asteroid Service Description json statements inside of a local Asteroid Service Description File"
__usage__ = """
Asteroid Add, will add Asteroid Service Descriptions to the Asteroid Service Description file located in located in your local Arcade TMPDIR.
This JSON file will have pointers to the Asteroid Service Descriptions paths under the services section of the document.
You will first need to run `arcade asteroid create` before running this tool along side of having Asteroid Service Descriptions uploaded using aracde asd upload. When adding in the Asteroid Service Descriptions use `arcade asteroid find --asd` to find the Asteroid Service Description you are looking for.

Examples:
    arcade asteroid add --asteroid test_asteroid --location asd/transactions/1/2022/05/04/01/43/95ed7bf5f81cbbdf0538a50a8ef2318c.json

    arcade asteroid add --asteroid test --location asd/transactions/1/2022/05/04/01/43/95ed7bf5f81cbbdf0538a50a8ef2318c.json -o service_options/desired_count=2

    arcade asteroid add --asteroid test --location asd/transactions/1/2022/05/04/01/43/95ed7bf5f81cbbdf0538a50a8ef2318c.json -c test_boolean=true
"""

import argparse
import boto3
import os
import sys

from arclib.asteroid import Asteroid

from arclib import storage, log, common


def main():
    """
    Defines Asteroid Service Descriptions inside of the Asteroid Service Description File
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__,
                                     formatter_class=argparse.RawTextHelpFormatter, prog='arcade asteroid add')
    requiredNamed = parser.add_argument_group('required arguments')

    requiredNamed.add_argument("-a", "--asteroid",
                               help="Asteroid Name, this is the name defined when using arcade asteroid create.",
                               required=True)

    requiredNamed.add_argument("-p", "--path", help="The S3 Path of the Asteroid Service Description", required=True)

    parser.add_argument("-o", "--override",
                        help="Overrides a section in the Asteroid Service Description with key value pair in the folowing format. key=value",
                        action='append')

    parser.add_argument("-c", "--config_override",
                        help="Application configuration data that can be added to the Asteroid Service Description with key value pair. key=value",
                        action='append')

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    tmp_dir = os.getenv("ATMP", '/tmp')

    if not Asteroid.id_validate(args.asteroid):
        print(f"Asteroid id needs to conform to {Asteroid.ASTEROID_ID_PATTERN}", file=sys.stderr)
        sys.exit(1)

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    asd_json = storage.s3_json_to_dict(session, bucket, args.path)
    if not asd_json:
        print(f"Not able to access {args.path} in s3 bucket {args.bucket}", file=sys.stderr)
        sys.exit(1)

    if args.override:
        overrides = args.override
    else:
        overrides = []

    asteroid_file = f'{tmp_dir}/{args.asteroid}.json'

    if args.config_override:
        config_overrides = args.config_override
    else:
        config_overrides = []

    asteroid = Asteroid()
    asteroid.from_file(asteroid_file)

    # Open the asd service file and validate the overrides
    asteroid.add_service(asd_json['service'], args.path)

    for override in overrides:
        asteroid.add_override(asd_json, override)

    for config_override in config_overrides:
        asteroid.add_config_override(asd_json, config_override)

    with open(asteroid_file, 'w') as json_file:
        json_file.write(asteroid.to_json())

    print(f"Asteroid {args.asteroid} is modified under {asteroid_file}")


if __name__ == "__main__":
    main()
