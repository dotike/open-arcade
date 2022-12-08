#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-setup -- Setup service definitions for a Galaga layer.
'''

# @depends: boto3, python (>=3.8)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Create a new local Galaga layer json document and add services to it."
__usage__ = "$ arcade galaga setup -A high_sun.arc -p gsd/asteroids-eks/default.json -p gsd/log-relay/default.json -o asteroids-eks:services/nodegroup/service_options/asteroids/nodes=6 --create"


import argparse
from datetime import datetime
import json
import os
import sys

import boto3

from arclib import common
from arclib import galaga
from arclib import log
from arclib import storage


def main():
    """
%(prog)s - Create a local Galaga json document and add services to it.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__description__,
        epilog=__usage__,
        prog="arcade galaga setup",
    )
    parser.add_argument("-A", "--arcade", help="Arcade name")
    parser.add_argument("-C", "--create", help="Create a new local config file", action="store_true")
    parser.add_argument("-p", "--path", help="S3 path to the gsd service json file", action='append')
    parser.add_argument("-d", "--dryrun", help="Dry run mode", action="store_true")
    parser.add_argument("-o", "--override", help="GSD service override service:key=value", action='append')
    parser.add_argument("--galaga-name", help="Set the 'name' field in the galaga file.", action='store')
    parser.add_argument("--galaga-version", help="Set the 'version' field in the galaga file.", type=int, action='store')
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

    galaga_name = arcade_name
    if args.galaga_name:
        galaga_name = args.galaga_name
    galaga_version = 1
    if args.galaga_version:
        galaga_version = args.galaga_version

    tmp_dir = os.getenv("ATMP", '/tmp')

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    if args.path:
        files = args.path
    else:
        files = []

    overrides = {}
    if args.override:
        for override in args.override:
            (service_name, service_override) = override.split(':', 1)
            if service_name in overrides:
                overrides[service_name].append(service_override)
            else:
                overrides[service_name] = [service_override]

    galaga_file = f'{tmp_dir}/{galaga_name}.json'
    if args.create:
        if os.path.exists(galaga_file):
            print(f"Galaga {galaga_name} already exists under {galaga_file}")
            sys.exit(1)
        else:
            # Create the new galaga from scratch.
            if not args.silent:
                print(f"Creating a new galaga {galaga_name} service definitions file.")
            galaga_dict = {
                            "user": os.getenv('USER', ''),
                            "createTime": '',
                            "name": galaga_name,
                            "version": galaga_version,
                            "components": {}
                          }
    else:
        # Here we are adding services to an existing galaga json file.
        galaga_dict = storage.load_json_file_to_dict(galaga_file)
        if not galaga_dict:
            print(f"File {galaga_file} doesn't exist. Add option '--create' to create it.")
            sys.exit(1)

    galaga_component = {}
    for service_file in files:
        gsd_json = storage.load_arcade_json_to_dict(bucket, service_file)
        if not gsd_json:
            print(f"Not able to access {service_file} in s3 bucket {bucket}")
            sys.exit(1)

        # Open the gsd service file and validate the overrides
        gsd_name = gsd_json['name']
        if not args.silent:
            print(f"Adding service {gsd_name} to the galaga {galaga_name} service definitions file.")
        galaga_component = galaga.add_component(galaga_dict, gsd_name, service_file)

        if gsd_name in overrides:
            for override in overrides[gsd_name]:
                try:
                    if not args.silent:
                        print(f"  Override parameter '{override}' for {gsd_name} to the galaga {galaga_name} service definitions file.")
                    galaga_component = galaga.add_override(galaga_component, gsd_json, override)
                except:
                    print(f"Invalid key in override '{override}' for service {gsd_name}")
                    sys.exit(1)

    if args.dryrun:
        if not args.silent:
            print(f"Dry run: Would create/modify Galaga named '{galaga_name}' in...")
            galaga_component['createTime'] = datetime.utcnow().strftime("%Y/%m/%d/%H/%M")
            print(f"{galaga_file}:\n" + json.dumps(galaga_component,
                                                   default=lambda o: o.__dict__,
                                                   sort_keys=False,
                                                   indent=4))
    else:
        if not galaga_component:
            galaga_component = galaga_dict
        galaga_component['createTime'] = datetime.utcnow().strftime("%Y/%m/%d/%H/%M")
        with open(galaga_file, 'w', encoding="utf-8") as json_file:
            json_file.write(json.dumps(galaga_component,
                                       default=lambda o: o.__dict__,
                                       sort_keys=False,
                                       indent=4) + "\n")

        if not args.silent:
            print(f"Galaga named '{galaga_name}' is modified in {galaga_file}")


if __name__ == "__main__":
    main()
