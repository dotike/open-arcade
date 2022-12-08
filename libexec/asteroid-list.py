#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)

__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "List running Asteroids and status of each service contained within them."
__usage__ = """
Displays the active running Asteroid for EKS for a given Arcade. The output by default is in tabbed output.
This will list the ID (Hydrated Asteroid ID), Status (Active or Not), Type (Containers, RDS), time of creation and modification timestamp on a Asteroid.
You can pass -j for output in JSON.
"""

import argparse
import json
import os
import boto3
import sys
from pprint import pprint
from arclib.narc_k8s import get_all_services

from arclib import log, k8s, common


def main():
    """
    Parses options that are passed at the command line.
    This function takes no arguments.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid list',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-A", "--arcade", help="Logical name of the arcade")
    parser.add_argument("-j", "--json", help="Output to STDOUT in JSON format.", action="store_true")
    args = parser.parse_args()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    output = False

    if args.json:
        output = "json"

    k8s.load_arcade_k8s_config(args.arcade)
    all_narc_deployments = get_all_services()

    asteroids = {}
    for deployment in all_narc_deployments:
        deployment_data = {}
        narc_id = deployment.metadata.name
        asteroid_name = narc_id[len('narc-'):narc_id.find('-', narc_id.find('-') + 1)]
        deployment_data['narc_id'] = narc_id
        deployment_data['asteroid_name'] = asteroid_name
        if deployment.status.available_replicas == deployment.status.replicas:
            deployment_data['status'] = "ACTIVE"
        else:
            deployment_data['status'] = "PENDING"
        deployment_data['ready'] = deployment.status.available_replicas
        deployment_data['replicas'] = deployment.status.replicas
        deployment_data['creation_timestamp'] = deployment.metadata.creation_timestamp
        deployment_data['last_update_time'] = deployment.status.conditions[0].last_update_time

        if asteroid_name in asteroids:
            asteroids[asteroid_name].append(deployment_data)
        else:
            asteroids[asteroid_name] = [deployment_data]

    _display_list_output(asteroids, output, args.arcade)


def list_db(arcade_name):
    client = boto3.client('rds')
    try:
        response = client.describe_db_instances()
        for db_instance in response['DBInstances']:
            for i in db_instance['TagList']:
                if i['Key'] == 'grv_name':
                    if i['Value'] == arcade_name:
                        db_instance_name = db_instance['DBInstanceIdentifier']
                        db_type = db_instance['DBInstanceClass']
                        db_status = (db_instance['DBInstanceStatus']).upper()
                        db_engine = db_instance['Engine']
                        db_created = str(db_instance['InstanceCreateTime'])
                        print("RDS: ", db_engine)
                        print(f"{'INSTANCE ID':<35s} {'STATUS':<13s} {'INSTANCE_TYPE':<15s} {'CREATED'}")
                        print(f"{db_instance_name:<35s} {db_status:<13s} {db_type:<15s} {db_created[:19]}")
    except client.exceptions.DBInstanceNotFoundFault as e:
        return 'Empty'


def _display_list_output(asteroids, output, arcade_name):
    """Display formatted list output to stdout"""

    TIME_FORMAT = "%FT%TZ"
    list_output = []
    for asteroid in asteroids:
        asteroid_content = {'asteroid_name': asteroid, 'services': []}

        for service in asteroids[asteroid]:
            narc_service = {'narc_id': service['narc_id'], 'status': service['status'], 'type': 'K8s',
                            'ready': f"{service['ready']}/{service['replicas']}",
                            'created': service['creation_timestamp'].strftime(TIME_FORMAT),
                            'modified': service['last_update_time'].strftime(TIME_FORMAT)}
            asteroid_content['services'].append(narc_service)

        list_output.append(asteroid_content)

    if output == "json":
        print(json.dumps(list_output, sort_keys=True, indent=4))
    else:
        for asteroid in list_output:
            print("")
            print(common.columnate(f"ASTEROID: {asteroid['asteroid_name']}"))
            print(f"{'NARC ID':<20s} {'STATUS':>21s} {'TYPE'} {'READY'} {'CREATED'} {'MODIFIED':>22s}")
            for narc_service in asteroid['services']:
                print(
                    f"{narc_service['narc_id']:<35s} {narc_service['status']} K8s {narc_service['ready']:>5s} {narc_service['created']:>21s} {narc_service['modified']:>21s}")
        list_db(arcade_name)


if __name__ == '__main__':
    main()
