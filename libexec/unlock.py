#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "force Unlock the s3 lock."
__usage__ = """
"""

import argparse
import os
import boto3
import sys
from arclib import storage, common


def main():
    """
# %(prog)s - Unlock the s3 buckets locked in state.
#     """
    parser = argparse.ArgumentParser(description=__description__,
                                     epilog=__usage__,
                                     prog='arcade unlock',
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("-A", "--arcade", help="Arcade name", required=False)
    parser.add_argument("-F", "--force", help="Force unlock", action='store_true')
    parser.add_argument("-G", "--galaga", help="Unlock galaga.lock", action='store_true')
    parser.add_argument("-R", "--reconcile", help="Unlock reconcile.lock", action='store_true')
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME')
        if not args.arcade:
            print("Arcade name missing, use -A/--arcade")
            parser.print_help()
            sys.exit(1)
    arcade_name = args.arcade
    session = boto3.session.Session()
    arcade_bucket = storage.get_arcade_buckets(session, arcade_name)['infrastructure']

    if args.galaga:
        Keys = ["galaga.lock"]
    elif args.reconcile:
        Keys = ["reconcile.lock"]
    else:
        Keys = ["galaga.lock", "reconcile.lock"]

    for key in Keys:
        if lock_busy(arcade_bucket, key):
            if args.force:
                unlock_bucket(arcade_bucket, key)
            else:
                if key == "galaga.lock":
                    print("Galaga Locks:")
                if key == "reconcile.lock":
                    print("Reconcile Locks:")
                print("arcade_bucket:", arcade_bucket, "key:", key, " Status:Locked")
                print("Force option missing, use -f/--force to unlock the locks")
                print("")
        else:
            if key == "galaga.lock":
                print("Galaga Locks:")
            if key == "reconcile.lock":
                print("Reconcile Locks:")
            print("No locks Present.")
            print("")


def lock_busy(arcade_bucket, key) -> bool:
    """Check whether the lock is busy"""
    conn = boto3.resource('s3')
    bucket = conn.Bucket(arcade_bucket)
    obj_list = list(bucket.objects.filter(Prefix=key))
    return len(obj_list) == 1 and obj_list[0].key == key


def unlock_bucket(arcade_bucket, key):
    conn = boto3.resource('s3')
    bucket = conn.Bucket(arcade_bucket)
    bucket.objects.filter(Prefix=key).delete()
    print("arcade_bucket:", bucket, " key:", key, " Status: Unlocked")


if __name__ == '__main__':
    main()
