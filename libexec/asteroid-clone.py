#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Clone an asteroid service description from current account to another account."
__usage__ = """
This program will clone a Asteroid Service Description from one AWS account to another. You will need to know the profile of the account,
the region and the Asteroid Service Description file path to execute this program. You can use arcade asteroid find --asteroid to find your
path to the ASD. Once the copy has happened you can switch accounts and run arcade asteroid find to verify that the path is present.

Example:

    $ arcade asteroid clone -A example.arc -f asteroid/example/1/2022/03/21/14/52/d4c82758f731fbe00d1104fb333a595f.json  -t awsprofilename -r us-east-2
        asd-2afff1d01a6b94fb75e4baa40e749435 asd/example/4/2022/05/16/16/46/44b07de731288ba3770701d93dcfb002.json
        asd-2afff1d01a6b94fb75e4baa40e749435 asteroid/example/1/2022/05/16/16/46/d4c82758f731fbe00d1104fb333a595f.json

    $ arcade asteroid clone --arcade example.arc --file asteroid/example/1/2022/03/21/14/52/d4c82758f731fbe00d1104fb333a595f.json  --target awsprofilename --region us-east-2
        asd-2afff1d01a6b94fb75e4baa40e749435 asd/example/4/2022/05/16/16/46/44b07de731288ba3770701d93dcfb002.json
        asd-2afff1d01a6b94fb75e4baa40e749435 asteroid/example/1/2022/05/16/16/46/d4c82758f731fbe00d1104fb333a595f.json
"""


import argparse
import boto3
import json
import os
import sys

from botocore.exceptions import ProfileNotFound
from arclib.asteroid import Asteroid
from arclib import ecr, storage, log, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid clone', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-A", "--arcade", help="Name of the Arcade", required=False)
    parser.add_argument("-v", "--verbose", help="Print verbose progress.", action="store_true")
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-f", "--file", help="Path to the Asteroid Service Description file. Use arcade asteroid find --asteroid to locate your path.", required=True)
    requiredNamed.add_argument("-t", "--target", help="Name of the target profile for the target AWS account", required=True)
    requiredNamed.add_argument("-r", "--region", help="The AWS region you are targeting", required=True)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)

    if not args.file:
        print("Asteroid file name is required", file=sys.stderr)
        sys.exit(1)

    if args.file:
        asteroid_file = args.file

    session = boto3.session.Session()

    if session.profile_name == args.target:
        print("Cannot clone asteroid on the same account", file=sys.stderr)
        sys.exit(1)

    bucket = storage.get_account_global_bucket(session)

    asteroid = Asteroid()
    asteroid.from_s3_object(bucket, asteroid_file)

    source_session = None
    target_session = None
    target_repositories = set()

    try:
        target_session = boto3.session.Session(
            profile_name=args.target, region_name=args.region)
        response = target_session.client('ecr').describe_repositories()
        target_repositories = set(x['repositoryName'] for x in response['repositories'])
    except ProfileNotFound as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    target_bucket = storage.get_account_global_bucket(target_session)

    for service in asteroid.services:
        asd_item = asteroid.services[service]['location']
        asd_obj = boto3.resource('s3').Object(bucket, asd_item)
        asd_content = asd_obj.get()['Body'].read().decode('utf-8')
        asd_json = json.loads(asd_content)
        for i in range(len(asd_json['containers'])):
            if args.verbose:
                print(f"Service = {asd_json['service']}")
                print(f"  Source Image Location =      {asd_json['containers'][i]['image']}")
            groups = asd_json['containers'][i]['image'].split('/')
            if len(groups) > 1:
                region = groups[0].split('.')[3]
                image_name = groups[1]
                if not source_session:
                    try:
                        source_session = boto3.session.Session(region_name=region)
                    except Exception as e:
                        print(e, file=sys.stderr)
                        sys.exit(1)

                repository = image_name.split(':')[0]
                if repository in target_repositories:
                    image_name = ecr.copy_image(source_session, target_session, image_name)
                else:
                    image_name = ecr.copy_image(source_session, target_session, image_name, repository)
                    target_repositories.add(repository)

                if args.verbose:
                    print(f"  Destination Image Location = {image_name}")
                asd_json['containers'][i]['image'] = image_name

        if args.verbose:
            print("ASD = ", end="", flush=True)
        new_asd_location = storage.upload_asteroid_json(target_session, target_bucket, 'asd',
                                                        asd_json['service'], asd_json['version'],
                                                        json.dumps(asd_json, sort_keys=False, indent=4),
                                                        silent=False)
        asteroid.services[service]['location'] = new_asd_location

    if args.verbose:
        print(f"Asteroid({asteroid.name}) = ", end="", flush=True)
    storage.upload_asteroid_json(target_session, target_bucket, 'asteroid',
                                 asteroid.name, asteroid.version, asteroid.to_json(),
                                 silent=False)


if __name__ == "__main__":
    main()
