#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Print tags associated with an asteroid or ASD to stdout."
__usage__ = """
Find all aliases available for the provided Asteroid or ASD service
These aliases are generated when `arcade asteroid alias` is run. 

Example Usage:

    $ arcade asteroid find-alias -a ${ASTEROID_NAME}

    $ arcade asteroid find-alias -s ${SERVICE_NAME}

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

    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid show-tags',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-a", "--asteroid",
                        help="Name of an asteroid")
    parser.add_argument("-s", "--service",
                        help="Name of a service (ASD)")
    parser.add_argument("-b", "--bucket",
                        help="Target bucket containing file.")

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.asteroid and not args.service:
        print("Either Asteroid name (--asteroid) or service name (--service) is required.", file=sys.stdout)
        sys.exit(1)

    if args.asteroid:
        prefix = f"asteroid/{args.asteroid}/"

    if args.service:
        prefix = f"asd/{args.service}/"

    session = boto3.session.Session()

    bucket = storage.get_account_global_bucket(session)

    if args.bucket:
        bucket = args.bucket

    ret = storage.find_s3_keys(session, bucket, prefix)
    if not ret:
        print(f"{prefix} not found!")
        sys.exit(1)

    if args.asteroid:
        print(f"Available aliases for asteroid {args.asteroid}:")
    elif args.service:
        print(f"Available aliases for ASD {args.service}:")

    for x in ret:

        alias = x[len(prefix):x.index(".json")]
        # Skip non alias files (look for / as only a sub dir or date radix formatted file would have one)
        if "/" not in alias:
            print(f"{alias} (s3://{x})")


if __name__ == "__main__":
    main()