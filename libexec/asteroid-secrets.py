#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Download or upload GALAGA JSON secrets"
__usage__ = """
This program will fetch secrets for a given Arcade. You have a few options with this tool. Cat will display your file
and or secrets to STDOUT. This tool will also upload and update secrets for a given arcade. Use load with local file to
upload secrets. When uploading the file needs to be in the same format as it was downloaded in JSON format.

Examples:

    $ arcade asteroid secrets -A ARCADE_NAME --asteroid ASTEROID_NAME --cat
    [
        {
            "secone": {
                "xxx": "xxxx"
            }
        },
        {
            "sectwo": {
                "xxxx": "xxxx"
            }
        },
    ]

    $ arcade asteroid secrets -A ARCADE_NAME --asteroid ASTEROID_NAME --cat > /path/to/somefile.json

    $ arcade asteroid secrets -A ARCADE_NAME --asteroid ASTEROID_NAME --local_file /Users/someuser/tmp/arcade/sec.json
    secone has been updated for $ARCADE_NAME
    sectwo has been updated for $ARCADE_NAME
"""

import argparse
import os
import ast
import sys
import json
import os.path
import botocore.exceptions

from arclib import secrets_manager, common


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=__description__, epilog=__usage__, prog='arcade asteroid secrets')
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument('-A', '--arcade', help='Name of the arcade', required=False)
    requiredNamed.add_argument('-a', '--asteroid', help='Name of the asteroid', required=True)
    parser.add_argument('-c', '--cat', action='store_true', help='Display Secrets to STDOUT')
    parser.add_argument('-f', '--file', help='local file for uploading secrets')

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)
    arcade_name = args.arcade

    if args.cat:
        list_of_sec = []
        arcade_secrets = secrets_manager.list_secrets(arcade_name=arcade_name)

        if arcade_secrets == []:
            print(f"No secrets found for {arcade_name}", file=sys.stderr)
            sys.exit(1)

        for items in arcade_secrets:
            if len(items.split('/')) > 2:
                if items.split('/')[0] == args.arcade:
                    if items.split('/')[1] == args.asteroid:
                        get_secrets = secrets_manager.get_secret(name=items)
                        final = ast.literal_eval(get_secrets)
                        final_set_dict = {
                            items: final
                        }
                        list_of_sec.append(final_set_dict)
                else:
                    print('Arcade not found!', file=sys.stderr)
                    sys.exit(1)

        print(json.dumps(list_of_sec, sort_keys=True, indent=4))
        sys.exit(0)
    elif args.file:
        filename = args.file
        file_exists = os.path.exists(filename)
        if file_exists:
            f = open(filename)
            data = json.load(f)
            for x in data:
                for key, value in x.items():
                    try:
                        secrets_manager.update_secret(name=key, secret_value=str(value))
                        print(f"{key} has been updated for {arcade_name}", file=sys.stdout)
                    except botocore.exceptions.ClientError as e:
                        secrets_manager.create_secret(name=key, secret_value=str(value))
                        print(f"{key} has been created for {arcade_name}", file=sys.stdout)
            sys.exit(0)
        else:
            print(f"File Not Found!", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
