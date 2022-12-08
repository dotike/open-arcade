#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = 'Displays the remote content of the Asteroid Service Description with a given path'
__usage__ = """
Displays the remote contents of a Asteroid Service Description, Asteroid Service Description or JSON schema file to STDOUT.
Asteroid Service Description (ASD) is a json document defining specific ASDs (Asteroid Service Description) for a Asteroid.
Asteroid Service Description (ASD) is a json document defining a specfic Asteroid services in a JSON document.

Use `arcade asteroid find` to find the file path of your choosing.

Examples:
    arcade asteroid cat --path [PATH]
    arcade asteroid cat --path asteroid/tinysun/1/2022/04/28/12/54/ce37207944a35bd188e3d0964edf80cf.json
    arcade asteroid cat --path $(arcade asteroid find | grep tinysun | grep 29/12/21)
"""


import argparse
import boto3
import sys
from botocore.exceptions import ClientError
from arclib import storage, log, common


def main():
    """
    Parses options that are passed at the command line. If no options are passsed then the method will not execute. 
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid cat' ,formatter_class=argparse.RawTextHelpFormatter)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-p", "--path", help="Path in the Asteroid Service Directory. Use (arcade asteroid find) to get your path.", required=True)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.path:
        print("A file path is required, please use arcade asteroid find for the correct path", file=sys.stderr)
        sys.exit(1)

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)
    s3_client = session.client('s3')

    try:
        s3_client.download_fileobj(bucket, args.path, sys.stdout.buffer)
    except ClientError as e:
        print(f"The file {args.path} was not found in the bucket {bucket}")
        sys.exit(1)
    print("")


if __name__ == '__main__':
    main()
