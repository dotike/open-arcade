#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Print out the tags associated with a GSD or GALAGA JSON."
__usage__ = """
Prints the tags associated with a given GSD to stdout. 
These tags are generated when `arcade galaga alias` is run. 

Example Usage:

    $ arcade galaga show-tags -p gsd/alb/default.json 

"""

import argparse
import logging
import sys

import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError

from arclib import storage, log, common


def printtagsout(bucket, filename, silent):
    """Print out the tags.

    :param s3_client: S3 client to work with
    :param bucket: Bucket to work from
    :param filename: File to get tags from
    :param silent: Toggle silence
    """
    s3_client = boto3.client('s3')
    try:
        response = s3_client.get_object_tagging(Bucket=bucket, Key=filename)
    except ClientError as c_e:
        logging.error(f"AWS error: {c_e}")
        return False
    except NoCredentialsError as crede:
        logging.error(f"AWS error: {crede}")
        return False

    print(filename)
    for tag in response['TagSet']:
        if silent:
            print(f"  {tag['Key']}={tag['Value']}")

    return True


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """

    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade galaga show-tags',
                                    formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-p", "--path",
                        help="Path to the file in S3")
    parser.add_argument("-b", "--bucket",
                        help="Target bucket containing file.  default is account scoped bucket.")
    parser.add_argument("-s", "--silent", action="store_false", help="Silence all output")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    filename = args.path
    if not filename.startswith(tuple(['gsd', 'galaga'])):
        print("-p/--path needs to start with gsd or galaga")
        sys.exit(1)

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)
    if args.bucket:
        bucket = args.bucket

    if not printtagsout(bucket, filename, args.silent):
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
