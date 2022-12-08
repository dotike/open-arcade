#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Uploads local container to ECR"
__usage__ = """
Uploads a docker image to ECR. This program will find the container locally on
your computer, peform a docker login, create ECR repository and finally will tag the container to ECR and upload.
This is arcade scoped program. You must have the image already pulled or built.

Examples:

    $ arcade ecr upload --arcade example.arc --container nginx --tag latest
    nginx has been uploaded to ECR at {account_number}.dkr.ecr.us-east-2.amazonaws.com/example.arc/nginx

    $ arcade ecr upload --arcade example.arc --container nginx
    nginx has been uploaded to ECR at {account_number}.dkr.ecr.us-east-2.amazonaws.com/example.arc/nginx
"""

import argparse
import os
import sys

from arclib import ecr, common


def main():
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade ecr upload',
                                     formatter_class=argparse.RawTextHelpFormatter)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-c", "--container", help='Name of the container')
    parser.add_argument("-A", "--arcade", help='Name of the aracade')
    parser.add_argument("-t", "--tag", help='Container Tag Name', default="latest")
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)

    upload_ecr_container = ecr.upload_container(
        arcade_name=args.arcade, local_container=args.container,
        _tag=args.tag
    )
    if upload_ecr_container[0]:
        print(f'{args.container} has been uploaded to ECR at {upload_ecr_container[1]}')
        sys.exit(0)
    else:
        print(f'{args.container} failed to upload to ECR')
        sys.exit(1)


if __name__ == '__main__':
    main()
