#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
report-all -- Generate report for a single arcade.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Generate report for a single arcade."


import argparse
import boto3
import json
import sys

from arclib import storage, log, common, k8s
from arclib.narc_k8s import get_k8s_info
from arclib.narc_ingress import get_ingress_info


def main():
    """
    %(prog)s - Generate report for a single arcade.
    """
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade report all')
    parser.add_argument("-A", "--arcade", help="Name of the arcade", required=True)
    parser.add_argument("-j", "--json", help="Display output in json format", action="store_true")
    parser.add_argument("-J", "--JSON", help="Display output in formatted json format", action="store_true")
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    session = common.setup_arcade_session(args.arcade)
    k8s.load_arcade_k8s_config(args.arcade)
    buckets = storage.get_arcade_buckets(session, args.arcade)

    if 'infrastructure' not in buckets:
        print("Invalid arcade name")
        sys.exit(1)

    infra_bucket = buckets['infrastructure']
    app_bucket = buckets['infrastructure']

    output = {'gravitar': storage.s3_json_to_dict(session, infra_bucket, 'gravitar/grv_info.json'),
              'galaga': storage.s3_json_to_dict(session, infra_bucket, 'galaga/galaga_info.json')}

    narc_keys = storage.find_s3_keys(session, app_bucket, 'narc/')

    asteroid_dict = {}

    for filename in narc_keys:
        asteroid_name = filename.split('/')[1].split('-')[0]
        if asteroid_name not in asteroid_dict:
            asteroid_dict[asteroid_name] = []

        asddata = storage.s3_json_to_dict(session, app_bucket, filename)
        if asddata['component_type'] == 'k8s':
            deployment, service = get_k8s_info(asddata)
            if not deployment:
                # service is not running
                continue

            asddata['running'] = {'deployment': deployment, 'service': service}
            if service and (asddata["service_options"]["load_balanced"]["public"] or
                            asddata["service_options"]["load_balanced"]["private"]):
                asddata['running']['loadbalancer'] = get_ingress_info(args.arcade, asddata)
        elif asddata['component_type'] == 'rds':
            pass

        asteroid_dict[asteroid_name].append(asddata)

    output['asteroid'] = asteroid_dict

    if args.JSON:
        print(json.dumps(output, sort_keys=True, indent=4, default=str))
    elif args.json:
        print(json.dumps(output, default=str))
    else:
        print(output)


if __name__ == "__main__":
    main()
