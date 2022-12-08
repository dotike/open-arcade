#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-
# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Displays the current runtime status of an Asteroid."
__usage__ = """
This program will display basic output of  the current status of a Asteroid. 
The component type, status, namespace, pod, pod ip, and public and private LB information will display to stdout.

Example:
  $ arcade asteroid show --asteroid exampleasteroid --arcade example.arc
        NARC ID: narc-exampleasteroid-nginxaarf
        Type: k8s
        Status: ACTIVE
        Ready: 1/1
        Namespace: exampleasteroid
        POD: narc-exampleasteroid-nginxaarf-594bdb5d54-l7c7m
        IP: 10.23.17.153
        Private LB: http://internal-private-example-arc-1681496406.us-east-2.elb.amazonaws.com:31054/
        Public LB: http://public-example-arc-1883311504.us-east-2.elb.amazonaws.com:31054/
        
  $ arcade asteroid show --asteroid exampleasteroid --arcade example.arc --JSON
    {
    "PODS": [
        {
            "ip": "10.23.17.153",
            "namespace": "exampleasteroid",
            "pod": "narc-exampleasteroid-nginxaarf-594bdb5d54-l7c7m"
        }
    ],
    "application_config": {
        "config_val_1": "foo",
        "config_val_2": "bar",
        "config_val_3": "baz"
    }......
    .......


"""
# TODO maybe needs better explanation, e.g. what does 'Asteroid state' mean here?


import argparse
from pprint import pprint
import json
import os
import sys
from botocore.exceptions import ClientError

from arclib import storage, log, common, k8s
from arclib.narc_k8s import get_k8s_info
from arclib.narc_ingress import get_ingress_info
from kubernetes import client, config

from arclib.asteroid import Asteroid


def main():
    """
    Parses options that are passed at the command line. 
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid show', formatter_class=argparse.RawTextHelpFormatter)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-a", "--asteroid", help="Name of the Asteroid", required=True)
    parser.add_argument("-A", "--arcade", help="Arcade name")
    parser.add_argument("-j", "--json", help="JSON output", action="store_true")
    parser.add_argument("-J", "--JSON", help="Pretty Print JSON output", action="store_true")
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME')
        if not args.arcade:
            print("Arcade name missing, use --arcade", file=sys.stderr)
            sys.exit(1)

    if not args.asteroid:
        print("Asteroid name (--asteroid) is required", file=sys.stderr)
        sys.exit(1)

    session = common.setup_arcade_session(args.arcade)
    if not session:
        print("AWS Authentication failed.", file=sys.stderr)
        sys.exit(1)
    k8s.load_arcade_k8s_config(args.arcade)

    arcade_buckets = storage.get_arcade_buckets(session, args.arcade)
    narcasds = storage.find_s3_keys(session, arcade_buckets['infrastructure'], f'narc/{args.asteroid}')
    if not narcasds:
        print(f"Asteroid: {args.asteroid} is not enabled", file=sys.stderr)
        sys.exit(1)

    arcade_domain = args.arcade.replace('_', '-').replace('.arc', '')

    for filename in narcasds:
        asddata = storage.s3_json_to_dict(session, arcade_buckets['infrastructure'], filename)

        if asddata['component_type'] == 'k8s':
            deployment, service = get_k8s_info(asddata)
            if not deployment:
                continue

            asddata['running'] = {}
            asddata['running']['deployment'] = deployment
            asddata['running']['service'] = service
            if service and (asddata["service_options"]["load_balanced"]["public"] or
                            asddata["service_options"]["load_balanced"]["private"]):
                ingress_data = get_ingress_info(args.arcade, asddata)
                asddata['running']['loadbalancer'] = ingress_data
        elif asddata['component_type'] == 'rds':
            pass
            # show_rds_instance(arcade_name=args.arcade, asd_data=asddata)

        if args.JSON:
            list_of_pods = []
            namespace_name = asddata['service'].split('-')[1]
            config.load_kube_config()
            v1 = client.CoreV1Api()
            ret = v1.list_namespaced_pod(namespace=namespace_name)
            for i in ret.items:
                list_of_pods.append({
                        'namespace': i.metadata.namespace,
                        'pod': i.metadata.name,
                        'ip': i.status.pod_ip,
                    })
            asddata['PODS'] = list_of_pods
            print(json.dumps(asddata, sort_keys=True, indent=4, default=str))
        elif args.json:
            print(json.dumps(asddata, default=str))
        else:
            if 'running' in asddata:
                running = asddata['running']
                running_dep = running['deployment']
                running_svc = running['service']
                print(f"NARC ID: {asddata['service']}")
                print(f"Type: {asddata['component_type']}")
                print(f"Status: {running_dep['status']}")
                print(f"Ready: {running_dep['ready']}/{running_dep['replicas']}")
                
                # List Container
                namespace_name = asddata['service'].split('-')[1]
                config.load_kube_config()
                v1 = client.CoreV1Api()
                ret = v1.list_namespaced_pod(namespace=namespace_name)
                for i in ret.items:
                    print(f"Namespace: {i.metadata.namespace}")
                    print(f"POD: {i.metadata.name}")
                    print(f"IP: {i.status.pod_ip}")
                
                if 'loadbalancer' in running:
                    if 'dns' in running['loadbalancer']['private']:
                        print(
                            f"Private LB: private-alb.{arcade_domain}.arc"
                            f" (http://{running['loadbalancer']['private']['dns']}:"
                            f"{running['loadbalancer']['private']['port']}"
                            f"{running['loadbalancer']['private']['path']})"
                            )
                    if 'dns' in running['loadbalancer']['public']:
                        print(
                            f"Public LB: public-alb.{arcade_domain}.arc"
                            f" (http://{running['loadbalancer']['public']['dns']}:"
                            f"{running['loadbalancer']['public']['port']}"
                            f"{running['loadbalancer']['public']['path']})")
            else:
                pprint(asddata)
            print()


if __name__ == "__main__":
    main()
