#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-find -- Given a path/prefix output a list of files in a S3 bucket.
'''

# @depends: boto3, python (>=3.9)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Lists paths from the Galaga Service Directory. Results can include Galaga Service Descrptions (GSD), Galaga Documents, and Hydrated Galaga Service Descriptions."
__usage__ = """
Displays the remote path of a Galaga Service Description (GSD), Galaga document, or Hydrated GSD in the Service Directory:

Galaga Service Description (GSD) is a json document defining a specific Galaga service in a JSON document.

Galaga Document is a json document defining specific Galaga Service Descriptions (GSDs) belonging to a Galaga.

Hydrated GSD is a json document that is the combination of a GSD combined with any overrides defined in the Galaga document.
The hydrated GSDs are the files that define the actual running services.

Examples:

Find all paths
    arcade galaga find

Limit search to specific named entity
    arcade galaga find --asd -n factortags
    arcade galaga find --asteroid -n aoa

Galaga Service Description
    arcade galaga find --gsd

    gsd/asteroids-eks/2/2022/08/12/15/00/99404512f919c9ba0094107b878ae005.json
    gsd/asteroids-msk/1/2022/05/04/19/00/a1b9fa5b30c12fd8aa2f2d4bd916d14b.json

Galaga Document
    arcade galaga find --galaga

    galaga/aoa-dev/1/2022/05/04/16/08/96256a87b888709447bbc32164e9b6fb.json
    galaga/aoax/2/2022/05/18/18/52/0fded0e5e65b2beb35ef11e525ae2246.json

Hydrated Galaga Service Descrption
    arcade galaga find --hydrated -A huge_hot.arc

    galaga/gsd/asteroids-eks.json
    galaga/gsd/asteroids-msk.json
    galaga/gsd/secretsmanager.json

"""

import argparse
import os
import sys

import boto3

from arclib import common
from arclib import log
from arclib import storage


def main():
    """
    %(prog)s - Given a path/prefix output a list of files in a S3 bucket.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade galaga find', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--gsd",
                        help="List GALAGA Service Descriptions",
                        action="store_true")
    parser.add_argument("--galaga",
                        help="List GALAGA documents",
                        action="store_true")
    parser.add_argument("--hydrated",
                        help="List Narc Service Descriptions",
                        action="store_true")
    parser.add_argument("-n", "--name",
                        help="Specify the name of a specific GSD or Galaga to limit the search to",
                        required=False,
                        default=None)
    parser.add_argument("-b", "--bucket",
                        help="Target bucket to search through. default is account scoped bucket.")
    parser.add_argument("-A", "--arcade",
                        help="The name of arcade.")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', '')

    if args.hydrated:
        if not args.arcade:
            print("-A/--arcade is required for finding hydrated.")
            sys.exit(1)

    if args.gsd:
        prefix = "gsd"
    elif args.galaga:
        prefix = "galaga"
    elif args.hydrated:
        prefix = "g"
    else:
        prefix = ''

    if args.hydrated:
        session = common.setup_arcade_session(args.arcade)
        buckets = storage.get_arcade_buckets(session, args.arcade)
        if 'infrastructure' not in buckets:
            print("Invalid arcade name.")
            sys.exit(1)
        bucket = buckets['infrastructure']
    else:
        session = boto3.session.Session()
        bucket = storage.get_account_global_bucket(session)
    if args.bucket:
        bucket = args.bucket

    if args.name:
        prefix = f"{prefix}/{args.name}"

    keys = storage.find_s3_keys(session, bucket, prefix)
    if not keys:
        sys.exit(1)
    for file in keys:
        print(file)

    sys.exit(0)


if __name__ == "__main__":
    main()
