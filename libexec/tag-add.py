#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
tag-arcade -- tags arcades and accounts

See Jira ticket IPTOOLS-477 and IPTOOLS-478

'''

# @depends: boto3, python (>=3.8)
import boto3
from arclib import tags, grv, log, common
import logging
import sys
import os
import argparse
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Tags every known resource in a single arcade or in every arcade in an AWS account. Use -A <arcade_name> to tag an arcade. Use -X to tag the current AWS account."
__usage__ = """
Tag Add uses the inventory tooling to generate a list of ARNs to tag in a given arcade. If the -X flag is used, it will tag every arcade with "arcade_tool_provisioned:<account_number>". For the time being, -X is hardcoded as a dryrun so that it can be tested without risk of actually tagging everything.

Examples:

Simple Tag (with yes-to-all to ignore prompts)
    arcade tag add -A <ArcadeName> -k my_tag -v exists -y

Verbose Dryrun Tag (good for seeing what you're about to do)
    arcade tag add -A <ArcadeName> -k my_tag -v exists --verbose -d

Account-Wide Tagging
    arcade tag add -X

"""


def main():
    """
    temp string
    """

    # The minimum version of python we support is 3.8
    MIN_PYTHON = (3, 8)
    if sys.version_info < MIN_PYTHON:
        sys.exit(f"Python {MIN_PYTHON} or later is required.\n")
        sys.exit(1)

    tool_name = os.path.basename(__file__)

    parser = argparse.ArgumentParser(description=__description__,
                                     epilog=__usage__,
                                     prog='arcade tag add',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-A', '--arcade', help='Arcade name')
    parser.add_argument('-X', '--account',
                        help='Tag an entire account', action="store_true")
    parser.add_argument('-k', '--key', help='Key name')
    parser.add_argument('-v', '--value', help='Value name')
    parser.add_argument('-d', '--dryrun', help='Print list of ARNs to tag',
                        action='store_true')
    parser.add_argument(
        '-y', '--yes', help="Yes to all (ignore prompts)", action='store_true')
    parser.add_argument("--verbose",
                        help="Increase output verbosity, default is WARNING",
                        action="count", default=0)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade and not args.account:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade and not args.account:
            print(
                "Arcade name or account flag must be specified.", file=sys.stderr)
            sys.exit(1)
    if not args.account and (not args.key or not args.value):
        print("Must specify key and value if not doing account-scoped tagging")
        sys.exit(1)

    log.set_log_level(args.verbose)

    if args.arcade:
        tags.tag(args.arcade, args.key, args.value,
                 dryrun=args.dryrun, yes_to_all=args.yes)
    elif args.account:
        # Step 1: Tag all the arcades
        grvs = grv.list_grvs()
        key = "arcade_tool_provisioned"
        value = ""
        try:
            value = boto3.client(
                'sts').get_caller_identity().get('Account')
        except:
            print("Unable to load account id")
            sys.exit(1)
        arcades = {}
        arcades_not_found = []
        for entry in grvs.values():
            region = entry['region']
            if region not in arcades.keys():
                arcades[region] = []
            for tag in entry['Tags']:
                if tag['Key'] == 'grv_name':
                    arcades[region].append(tag["Value"])
        print("Arcades whose resources will be tagged:")
        for region in arcades.keys():
            print(region)
            for name in arcades[region]:
                print(f"\t{name}")
        if not args.dryrun:
            print(f"Key: {key}\nValue: {value}")
            if not args.yes:
                conf = input(
                    "You are about to tag every arcade-related object in an account. This cannot be undone. Are you sure you want to continue? [y/n] ")
                if conf.lower() != "y":
                    print("Aborting")
                    sys.exit(0)
            # first loop through and tag arcades
            for region in arcades:
                grv.set_region(region)
                for arcade in arcades[region]:
                    # for safety, this will always be dryrun until this tool is approved for production use
                    result = tags.tag(arcade, key,
                                      value, dryrun=True)
                    if result:
                        arcades_not_found.append(result)
            grv.set_region()
        # Step 2: Tag account-wide items # Not needed for now
        # Step 3: List Orphans
        if len(arcades_not_found) > 0:
            print(
                "The following arcades were skipped that do not have Gravitar Manifests.")
            print("They are most likely orphaned from the deletion process.")
            for arcade in arcades_not_found:
                print(f"\t{arcade}")
    sys.exit(0)
    # End of main


if __name__ == '__main__':
    main()
