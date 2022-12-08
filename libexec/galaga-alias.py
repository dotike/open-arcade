#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Creates or updates a named alias of a GSD."
__usage__ = """
Alias functions by making a copy of the GSD file specified by --path. 
It will tag the asteroid with the name specified by -t.

Example usage:

    $ arcade galaga alias -p gsd/alb/default.json -t example-alias

    This creates a copy of test.json at gsd/alb/default.json. You can find it with 
    `arcade galaga find --gsd`
"""

import sys
import argparse
import boto3


from arclib import storage, log, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """

    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade galaga alias',
                                    formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-p", "--path",
                        help="Path to the file in S3")
    parser.add_argument("-t", "--tag", required=True,
                        help="Tag to give the alias")
    parser.add_argument("-b", "--bucket",
                        help="Target bucket containing file.")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    filename = args.path
    if not filename.startswith(tuple(['gsd', 'galaga'])):
        print("-p/--path needs to start with gsd or galaga")
        sys.exit(1)
    tag = args.tag

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)
    if args.bucket:
        bucket = args.bucket

    service_name = filename.split("/")
    alias = f"{service_name[0]}/{service_name[1]}/{tag}.json"

    s3_client = session.client('s3')
    copysource = {'Bucket': bucket, 'Key': filename}
    tagline = f"original={filename}"
    s3_client.copy_object(Bucket=bucket, CopySource=copysource,
                          Key=alias, TaggingDirective='REPLACE', Tagging=tagline)

    sys.exit(0)


if __name__ == "__main__":
    main()
