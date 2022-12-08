#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Lists paths from the Asteroid Service Directory. Results can include Asteroid Service Descrptions (ASD), Asteroid Documents, and Hydrated Asteroid Service Descriptions."
__usage__ = """
Displays the remote path of Asteroid Service Descriptions (ASD), Asteroid documents, or Hydrated Asteroid Service Descriptions from the Service Directory.

Asteroid Service Description is a json document defining a specific Asteroid services in a JSON document.

Asteroid Document is a json document defining specific Asteroid Service Descriptions (ASDs) belonging to an Asteroid.

Hydrated ASD is a json document that is the combination of a ASD combined with any overrides defined in the Asteroid document.
The hydrated ASDs are the files that define the actual running services.

Examples:

Find all paths
    arcade asteroid find

Limit search to specific named entity
    arcade asteroid find --asd -n factortags
    arcade asteroid find --asteroid -n aoa

Asteroid Service Description
    arcade asteroid find --asd
    
    asd/example/1/2022/03/18/20/44/95ed7bf5f81cbbdf0538a50a8ef2318c.json
    asd/example/4/2021/10/04/23/08/d093fea196ee3745e5b5effa987a647b.json

Asteroid Document 
    arcade asteroid find --asteroid
    
    asteroid/example/1/2021/09/29/18/51/69108434bc16dbad1b6a133c467de259.json
    asteroid/example/1/2021/09/29/19/13/69108434bc16dbad1b6a133c467de259.json

Hydrated Asteroid Service Descrption
    arcade asteroid find --hydrated -A huge_hot.arc
    
    narc/aoax-apilb.json
    narc/aoax-comp-server.json
    narc/aoax-factortags.json
    narc/aoax-iverson.json
    narc/aoax-maxwell.json
    narc/aoax-memcache.json
    narc/aoax-reportgeneration.json
    narc/aoax-rest-api-global-tasks.json
    narc/aoax-rest-api-server.json
    narc/aoax-securitymaster.json
    narc/aoax-snapshots.json
    narc/aoax-taxlot-data.json
    narc/aoax-transactions.json

"""

import boto3
import argparse
import os
import sys
import json

from arclib import storage, log, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    This function will still execute even with no command line options passed.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid find', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--asd",
                        help="List Asteroid Service Descriptions paths from the Service Directory",
                        action="store_true")

    parser.add_argument("-a", "--asteroid",
                        help="List Dehydrated Asteroid Service Descriptions paths from the Service Directory",
                        action="store_true")

    parser.add_argument("--hydrated",
                        help="List Hydrated Asteroid Documents",
                        action="store_true")

    parser.add_argument("-n", "--name",
                        help="Specify the name of a specific ASD or Asteroid to limit the search to",
                        required=False,
                        default=None)

    parser.add_argument("-A", "--arcade", help='Specify Arcade to view Hydrated Arcade Context')
    parser.add_argument('-E', '--enabled_asteroid', help='Dispalys the path to the enabled asteroid', action="store_true")

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if args.asd:
        prefix = "asd"
    elif args.asteroid:
        prefix = "asteroid"
    elif args.hydrated:
        prefix = "narc"
    else:
        prefix = ''

    session = boto3.session.Session()
    global_bucket = storage.get_account_global_bucket(session)

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', '')

    if prefix == 'narc':
        if not args.arcade:
            print("arcade is required for finding hydrated paths, please set arcade name using arcade documentation.", file=sys.stderr)
            sys.exit(1)

    buckets = storage.get_arcade_buckets(session, args.arcade)
    if 'infrastructure' not in buckets:
        print("Invalid arcade name, please set arcade name using arcade documentation.", file=sys.stderr)
        sys.exit(1)

    infra_bucket = buckets['infrastructure']

    if args.enabled_asteroid:
        keys = storage.find_s3_keys(session, infra_bucket, 'narc')
        if len(keys) < 1:
            sys.exit(1)
        else:
            s3_client = boto3.client('s3')
            s3_response_object = s3_client.get_object(Bucket=infra_bucket, Key=keys[0])
            x = s3_response_object['Body'].read()
            data = json.loads(x.decode('utf-8'))
            print(data['asteroid_json'])
    else:
        if prefix == "narc":
            bucket = infra_bucket
        else:
            bucket = global_bucket

        if args.name:
            prefix = f"{prefix}/{args.name}"
        ret = storage.find_s3_keys(session, bucket, prefix)
        if not ret:
            sys.exit(1)
        for x in ret:
            print(x)


if __name__ == "__main__":
    main()
