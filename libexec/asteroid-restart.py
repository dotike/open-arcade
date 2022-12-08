#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)


__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Triggers a restart of a service"
__usage__ = """
Enables a user to "restart" an Asteroid, or a single service within an Asteroid.
This tool will update the "desired_state" field within appropriate Hydrated ASDs with "restart".
This flag will tell reconcile to perform a rolling deploy in Kubernetes to kill and restart all pods in the deployment 
in a zero downtime fashion.
"""

import argparse
import boto3
import sys
import os

from arclib.asteroid import Asteroid
from arclib.eks import get_eks_clusters_detail
from arclib import storage, log, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid enable',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-A", "--arcade", help='The name of the Arcade', required=False)
    parser.add_argument("-s", "--service", help="", required=False, default=None)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-p", "--path",
                               help="Path to the Dehydrated Asteroid file. This creates a Hydrated Asteroid Arcade config. Use arcade asteroid find to locate your dehydrated asteroid file.",
                               required=False)

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)

    if not args.path:
        print("PATH (--path) is required", file=sys.stdout)
        sys.exit(1)

    if args.path:
        asteroid_file = args.path

    session = boto3.session.Session()
    source_bucket = storage.get_account_global_bucket(session)

    eks_stat = get_eks_clusters_detail(arcade_name=args.arcade)
    if not eks_stat:
        print(
            "No response when checking EKS status. Please ensure Galaga is correctly configured before restarting an Asteroid (see 'arcade galaga run')")
        exit(1)

    buckets = storage.get_arcade_buckets(session, args.arcade)

    if 'infrastructure' not in buckets:
        print("Invalid arcade name or arcade bucket does not exist", file=sys.stdout)
        sys.exit(1)

    asteroid = Asteroid()
    asteroid.from_s3_object(source_bucket, asteroid_file)

    asteroid.set_restart(source_bucket, buckets['infrastructure'], False, asteroid_file, 'narc', args.service)


if __name__ == "__main__":
    main()
