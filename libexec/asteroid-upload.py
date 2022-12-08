#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Uploads a dehydrated asteroid service description from local computer to the arcade scoped storage"
__usage__ = """
Uploads a dehydrated Asteroid Service Description to the Asteroid Service Driectory .
You can either pass a file to the json document or just provide the asteroid name that was
used when running arcade asteroid create.
This should be run after arcade asteroid create and arcade asteroid add.
After running this tool you should be able to run arcade asteroid enable to hydrate the configuration.

Example:
    arcade asteroid upload -f /Users/SOME_USER/tmp/arcade/example.json

    arcade asteroid upload -a example

"""


import argparse
import boto3
import os
import sys
from arclib.asteroid import Asteroid
from arclib import storage, log, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid upload', formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--asteroid", help="The logical name of the Asteroid specified when running arcade asteroid create.", required=False)
    group.add_argument("-f", "--file", help="Full local file path to the created asteroid json document in the TMPDIR.", required=False)
    parser.add_argument("-t", "--tag", action="store", default="",
                        help="Create an alias with this tag name.\n(i.e.: 'raw_egg/asteroid-name/service-name' => 'asd/raw_egg/asteroid-name/service-name.json')")

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    tmp_dir = os.getenv("ATMP", '/tmp')

    if not args.asteroid and not args.file:
        print("Either asteroid name (--asteroid) or file name (--file) is required", file=sys.stdout)
        sys.exit(1)

    filename = None

    if args.asteroid:
        if Asteroid.id_validate(args.asteroid):
            filename = f"{tmp_dir}/{args.asteroid}.json"
        else:
            print(f"Asteroid id needs to conform to {Asteroid.ASTEROID_ID_PATTERN}", file=sys.stdout)
            sys.exit(1)
    # -f option overrides -a option
    if args.file:
        filename = args.file

    if not os.path.exists(filename):
        print(f"The asteroid json file {filename} does not exist", file=sys.stdout)
        sys.exit(1)

    asteroid = Asteroid()
    asteroid.from_file(filename)

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    for name, service in asteroid.services.items():
        if name != service['location'].split('/')[1]:
            print(f"Invalid asteroid service {name} != {service['location'].split('/')[1]}", file=sys.stdout)
            sys.exit(1)
        if not storage.find_s3_keys(session, bucket, service['location']):
            print(f"Asd file {service['location']} does not exist in s3", file=sys.stdout)
            sys.exit(1)

    s3loc = storage.upload_asteroid_json(session, bucket, 'asteroid',
                                         asteroid.name, asteroid.version,
                                         asteroid.to_json(), False,
                                         tagpath=args.tag)
    if not s3loc:
        sys.exit(1)


if __name__ == '__main__':
    main()
