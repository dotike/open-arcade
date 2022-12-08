#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Print tags associated with an asteroid or ASD to stdout."
__usage__ = """
Find the source file referenced by an alias.
These aliases are generated when `arcade asteroid alias` is run. 

Example Usage:

    $ arcade asteroid show-alias -a ${ASTEROID_NAME} -t ${ALIAS_NAME} 
    
    $ arcade asteroid show-alias -s ${SERVICE_NAME} -t ${ALIAS_NAME}

"""

import sys

import argparse
import boto3

from arclib import storage, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """

    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid show-tags', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-a", "--asteroid",
                        help="Name of an asteroid")
    parser.add_argument("-s", "--service",
                        help="Name of a service (ASD)")
    parser.add_argument("-t", "--alias",
                        help="Name of alias to inspect")
    parser.add_argument("-b", "--bucket",
                        help="Target bucket containing file.")

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.asteroid and not args.service:
        print("Either Asteroid name (--asteroid) or service name (--service) is required.", file=sys.stdout)
        sys.exit(1)

    if not args.alias:
        print("Alias (--alias) is required", file=sys.stdout)
        sys.exit(1)

    if args.asteroid:
        filename = f"asteroid/{args.asteroid}/{args.alias}.json"

    if args.service:
        filename = f"asd/{args.service}/{args.alias}.json"

    session = boto3.session.Session()

    bucket = storage.get_account_global_bucket(session)

    if args.bucket:
        bucket = args.bucket

    s3_client = session.client('s3')
    response = s3_client.get_object_tagging(Bucket=bucket, Key=filename)

    original = None
    for tag in response['TagSet']:
        if tag['Key'] == "original":
            original = tag['Value']

    if original:
        if args.asteroid:
            print(f"Alias {args.alias} ({filename}) associated with Asteroid {original}")
        if args.service:
            print(f"Alias {args.alias} ({filename}) associated with ASD {original}")

    else:
        print(f"No original tag detected on object {filename}")

    sys.exit(0)


if __name__ == "__main__":
    main()