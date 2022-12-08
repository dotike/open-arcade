#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "This will download a Dehydrated Asteroid Service Description on your local computer"
__usage__ = """
Downloads a Dehydrated Asteroid Service Description JSON file to the TMPDIR. Similar to asteroid cat, but instead of
the content going to stdout, this will download the file to the TMDIR. You can use arcade asteroid find to locate the remote file path.

Example:
    $ arcade asteroid download --path asteroid/example/1/2022/04/28/12/54/ce37207944a35bd188e3d0964edf80cf.json  --arcade example.arc

      Dehydrated Asteroid Service Description located at /Users/someuser/tmp/arcade/example.json

    $ arcade asteroid download -p $(arcade asteroid find --asteroid | grep woofaarf | grep "09/22/20/00") --arcade example.arc

      Dehydrated Asteroid Service Description located at /Users/someuser/tmp/arcade/example.json
"""

import argparse
import boto3
import os
import sys

from arclib import storage, log, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid download', formatter_class=argparse.RawTextHelpFormatter)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-p", "--path", help="This is the dehydrated asteroid configuration file path. Use arcade asteroid find to locate the file path", required=True)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if args.path:
        asteroid_path = args.path
        asteroid_name = args.path.split('/')[1]

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    tmp_dir = os.getenv("ATMP", '/tmp')

    s3_client = session.client('s3')

    keys = storage.find_s3_keys(session, bucket, asteroid_path)

    if len(keys) != 1:
        print("Invalid asteroid pathname in s3.", file=sys.stderr)
        sys.exit(1)

    with open(f"{tmp_dir}/{asteroid_name}.json", "wb") as output_file:
        s3_client.download_fileobj(bucket, keys[0], output_file)

    print(f"Dehydrated Asteroid Service Description located at {tmp_dir}/{asteroid_name}.json", file=sys.stdout)

if __name__ == '__main__':
    main()
