#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Creates or updates a named alias of an asteroid or ASD."
__usage__ = """
Alias functions by making a copy of the asteroid or ASD file specified by --path.
It will tag the asteroid with the name specified by -t.

Example usage:

    $ arcade asteroid alias -p asd/nginxwoof/test.json -t deleteme

    This creates a copy of test.json at asd/nginxwoof/deleteme.json. You can find it with:
    $ arcade asteroid find --asd

    You can view the copy with:
    $ arcade asteroid cat -p asd/nginxwoof/deleteme.json

    You can display the tag on the copy with:
    $ arcade asteroid show-tags -p asd/nginxwoof/deleteme.json
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

    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid alias', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-p", "--path",
                        help="Path to the file in S3")
    parser.add_argument("-t", "--tag",
                        help="Tag to give the alias")
    parser.add_argument("-b", "--bucket",
                        help="Target bucket containing file.")

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.path:
        print("S3 path (--path) is required", file=sys.stdout)
        sys.exit(1)

    filename = args.path
    tag = args.tag

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    if args.bucket:
        bucket = args.bucket

    service_name = filename.split("/")
    alias = '{}/{}/{}.json'.format(service_name[0], service_name[1], tag)

    s3_client = session.client('s3')
    copysource = {'Bucket': bucket, 'Key': filename}
    tagline = 'original={}'.format(filename)
    s3_client.copy_object(Bucket=bucket, CopySource=copysource,
                          Key=alias, TaggingDirective='REPLACE', Tagging=tagline)
    sys.exit(0)


if __name__ == "__main__":
    main()
