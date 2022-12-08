#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)


__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Creates/Pushes a Hydrated Arcade Configuration file for a specific ARCADE, only hydrates configuration.  (see `narc reconcile` to run the Asteroid)"
__usage__ = """
Pushes a Hydrated Arcade Configuration file to a specific arcade..
This enables an Asteroid to be run in this arcade, reconcile operations use these hydrated configs to actually run services.
After running this program you can use arcade asteroid find -A to see the path of the Hydrated Asteroid configuration. After running this program you can run an Arcade using arcade narc reconcile -A, which will actually run all services in a given ARCADE.
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
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid enable', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-A", "--arcade", help='The name of the Arcade', required=False)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-p", "--path", help="Path to the Dehydrated Asteroid file. This creates a Hydrated Asteroid Arcade config. Use arcade asteroid find to locate your dehydrated asteroid file.", required=True)
    
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
        print("No response when checking EKS status. Please ensure Galaga is correctly configured before enabling an Asteroid (see 'arcade galaga run')")
        exit(1)

    buckets = storage.get_arcade_buckets(session, args.arcade)

    if 'infrastructure' not in buckets:
        print("Invalid arcade name or arcade bucket does not exist", file=sys.stdout)
        sys.exit(1)


    asteroid = Asteroid()
    asteroid.from_s3_object(source_bucket, asteroid_file)

    asteroid.to_narc(source_bucket, buckets['infrastructure'], False, asteroid_file, 'narc')


if __name__ == "__main__":
    main()
