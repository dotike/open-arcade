#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Disable an Asteroid to run in a given ARCADE"
__usage__ = """
Disable a Asteroid. After running this program you may want to verify the Asteroid has been disabled in the target Arcade.
You can check it by using arcade asteroid find -A

Example:

    Find the active hydrated asteroid service description
        
        $ arcade asteroid find -A
          narc/exampleasteroid-nginxaarf.json
          narc/exampleasteroid-nginxwoof.json
          narc/exampleasteroid-rdsservice.json
    
    Disable using asteroid name:
        
        $ arcade asteroid disable --arcade example.arc --asteroid exampleasteroid
        
        $ arcade asteroid disable -A example.arc -a exampleasteroid
    
    Disable using file path:
        
        $ arcade asteroid disable --arcade example.arc --path narc/exampleasteroid-nginxaarf.json
        
        $ arcade asteroid disable -A example.arc -p narc/exampleasteroid-nginxaarf.json
        
        $ arcade asteroid disable -A example.arc -p $(arcade asteroid find -A |  head -n 1)
"""

import argparse
import os
import boto3
import sys

from arclib.asteroid import Asteroid
from arclib.eks import get_eks_clusters_detail

from arclib import storage, log, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """
    
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid disable', formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-A", "--arcade", help='The name of the Arcade', required=False)
    group.add_argument("-p", "--path", help="Path to the Hydrated Asteroid file. Use arcade asteroid find to locate your enabled asteroid file.")
    group.add_argument("-a", "--asteroid", help='Logical name of asteroid. Same name when using arcade asteroid create')
    
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.asteroid and not args.path:
        print("Either asteroid name (--asteroid) or path (--path) is required", file=sys.stdout)
        sys.exit(1)
    
    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)
    

    if args.asteroid:
        asteroid_name = args.asteroid
        asteroid_file = asteroid_name
    
    if args.path:
        asteroid_file = args.path
        asteroid_name = asteroid_file.split('/')[1].split('-')[0]
        
    session = boto3.session.Session()

    eks_stat = get_eks_clusters_detail(arcade_name=args.arcade)
    if not eks_stat:
        print("No response when checking EKS status. Please ensure Galaga is correctly configured (see 'arcade galaga run')")
        exit(1)

    buckets = storage.get_arcade_buckets(session, args.arcade)

    if 'infrastructure' not in buckets:
        print("Invalid arcade name or arcade bucket does not exist", file=sys.stdout)
        sys.exit(1)

    storage.delete_s3_prefix(session, buckets['infrastructure'], f"narc/{asteroid_name.lower()}-")


if __name__ == "__main__":
    main()
