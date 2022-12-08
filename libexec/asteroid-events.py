#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Display event stream for specified Asteroid. Displays a timestamp and a message when events are present."
__usage__ = """
To run this program use the asteroid name and arcade name (Logical Names). This will show events for a given
Arcade/Asteroid. If there are no events then the program will state there are no events.

Example:
    $ arcade asteroid events --asteroid exampleasteroid --arcade example.arc
        No events found for asteroid exampleasteroid
    
    For JSON output pass in --JSON
    $ arcade asteroid events --asteroid exampleasteroid --arcade example.arc --JSON
"""


import argparse
import json
import os
import sys
from pprint import pprint
from arclib.narc_k8s import get_events_for_service

from arclib import log, k8s, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid events', formatter_class=argparse.RawTextHelpFormatter)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-a", "--asteroid", help="Name of the asteroid", required=True)
    parser.add_argument("-A", "--arcade", help="Name of the Arcade")
    parser.add_argument("-j", "--json", help="JSON output", action="store_true")
    parser.add_argument("-J", "--JSON", help="Pretty Print JSON output", action="store_true")
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)

    if not args.asteroid:
        print("Asteroid id is required", file=sys.stderr)
        sys.exit(1)

    output = False
    
    if args.JSON:
        output = "pretty"
    elif args.json:
        output = "json"

    k8s.load_arcade_k8s_config(args.arcade)
    events = get_events_for_service(args.asteroid)

    if events:
        if output == "json":
            print(json.dumps(events))
        elif output == "pretty":
            pprint(events)
        else:
            for event in events:
                print(
                    "{}\t{}\n".format(
                        event["timestamp"],
                        event["message"],
                    )
                )
    else:
        print(f"No events found for asteroid {args.asteroid}")


if __name__ == '__main__':
    main()
