#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
set-owner -- This will display/modify owner of an Arcade.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "This will display/modify owner of an Arcade."


import argparse
import os
import sys

from arclib import grv, common, log


def main():
    """
    %(prog)s - This will display/modify owner of an Arcade.
    """
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade set owner')
    parser.add_argument("-A", "--arcade", help="Name of the arcade")
    parser.add_argument("-o", "--owner", help="add/modify the owner")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if not args.arcade:
        args.arcade = os.environ.get('ARCADE_NAME')

    if not args.arcade:
        print("Arcade name required")
        sys.exit(1)

    session = common.setup_arcade_session(args.arcade)

    if args.owner:
        grv.update_grv_tag(session, args.arcade, 'owner', args.owner)
        print(f"add/modify the owner to {args.owner}")
    else:
        owner = grv.find_grv_tag(session, args.arcade, 'owner')
        print(f"owner: {owner}")


if __name__ == '__main__':
    main()
