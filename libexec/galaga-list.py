#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-list -- This will list Galaga modules installed in the provided Arcade
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "This will list Galaga modules installed in the provided Arcade."

import argparse
import asyncio
import os, json
import sys

from arclib import grv, log, msk, alb, asg, promethus, common
from inventory import list_galaga_objects


async def main():
    """
    %(prog)s - This will "list" Galaga modules installed in the provided Arcade
    """
    parser = argparse.ArgumentParser(description=main.__doc__, prog='arcade galaga list')
    parser.add_argument("-A", "--arcade", help="Name of the arcade", required=False)
    parser.add_argument("-J", "--json", help='Output in JSON format', action='store_true')
    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME', "")
        if not args.arcade:
            print("Arcade name missing, use --arcade or `export ARCADE_NAME=<name>", file=sys.stderr)
            sys.exit(1)

    arcade = args.arcade

    buckets = grv.list_arcade_buckets(arcade)

    if not buckets:
        print("Invalid arcade name")
        sys.exit(1)

    infra_bucket = buckets['infrastructure']

    x = list_galaga_objects(arcade, True)
    information_dict = {}
    list_of_modules = []
    for file in os.listdir("libexec/galaga-modules"):
        list_of_modules.append(file)

    if 'log-relay' in list_of_modules:
        arcade_nlb = arcade.replace('_', '').replace('.', '-')
        arcade_asg = arcade.replace('_', '-')
        nlb_present = False
        list_of_lb = alb.get_list_lb()

        if f'log-relay-privatenlb-{arcade_nlb}' in list_of_lb:
            nlb_present = True
        else:
            nlb_present = False

        if nlb_present:
            information_dict['log-relay-nlb'] = {
                'Present': True,
                'NLB_NAME': f'log-relay-privatenlb-{arcade_nlb}'
            }
        else:
            information_dict['log-relay-nlb'] = {
                'Present': False,
                'NLB_NAME': False
            }

        asg_info = asg.get_asg_info(f'log-relay.{arcade_asg}')

        if asg_info:
            if asg_info['AutoScalingGroupName'] == f'log-relay.{arcade_asg}':
                information_dict['log-relay-asg'] = {
                    'Present': True,
                    'ASG_NAME': f'log-relay.{arcade_asg}'
                }
        else:
            information_dict['log-relay-asg'] = {
                'Present': False,
                'ASG_NAME': False
            }

    if 'asteroids-eks' in list_of_modules:
        info = x['eks_cluster']
        if info == '':
            information_dict['EKS'] = ''
            information_dict['ASG'] = ''
            information_dict['LB'] = ''
            information_dict['eks_nodegroup'] = ''
        else:
            information_dict['EKS'] = info['arn']
            information_dict['ASG'] = x['auto_scale_group_list']
            information_dict['LB'] = x['lbList']
            information_dict['eks_nodegroup'] = x['eks_nodegroup']

    if 'secretsmanager' in list_of_modules:
        check = grv.check_if_arcade_policy(arcade, 'SecretsManager')
        if check:
            information_dict['SecretsManager'] = True
        else:
            information_dict['SecretsManager'] = False

    if 'galagazero' in list_of_modules:
        # TODO Need to figure out how to tell if Galaga Zero is installed or not
        information_dict['galagazero'] = False

    if 'asteroids-msk' in list_of_modules:
        x = arcade.replace('_', '').replace('.', '-')
        status = msk.get_msk_status(cluster_name=f'asteroids-{x}')
        if status == {}:
            information_dict['MSK'] = False
        else:
            information_dict['MSK'] = status['ClusterName']

    if 'parameterstore' in list_of_modules:
        check = grv.check_if_arcade_policy(arcade, 'parameterstore')
        if check:
            information_dict['parameterstore'] = True
        else:
            information_dict['parameterstore'] = False

    if 'prometheus' in list_of_modules:
        # CHECK GRAFANA
        status = False
        check_graphana = promethus.get_prometheus_grafana_role(arcade_name=arcade, application='grafana')
        if check_graphana:
            status = True
        else:
            status = False

        if status:
            get_grafana_url = promethus.get_grafana_url(arcade_name=arcade)
            information_dict['grafana'] = {'status': True, 'url': f'https://{get_grafana_url}'}
        else:
            information_dict['grafana'] = False

    if 'prometheus' in list_of_modules:
        # CHECK PROMETHEUS
        status = False
        check_prometheus = promethus.get_prometheus_grafana_role(arcade_name=arcade, application='prometheus')
        if check_prometheus:
            status = True
        else:
            status = False

        if status:
            information_dict['prometheus'] = {'status': True,
                                              'endpoint': promethus.get_aws_prometheus_workspace_id(arcade_name=arcade)}
        else:
            information_dict['prometheus'] = False

    if not args.json:
        print(f"Arcade: {arcade}")
        print('')
        print('Componet\tStatus\t\tResource')
        print('')

        # EKS
        if information_dict['EKS'] == '':
            print(f"EKS\t\tInactive\t\t")
        else:
            print(f"EKS\t\tActive\t\t{information_dict['EKS'].split('/')[1]}")

        # PROMETHEUS
        if not information_dict['prometheus']:
            print(f"PROMETHEUS\tInactive\t\t")
        else:
            print(f"PROMETHEUS\tActive\t\t{information_dict['prometheus']['endpoint']}")

        # # Grafana
        if not information_dict['grafana']:
            print(f"GRAFANA\t\tInactive\t\t")
        else:
            print(f"GRAFANA\t\tActive\t\t{information_dict['grafana']['url']}")

        # ASG
        if information_dict['ASG'] == '':
            print(f"ASG\t\tInactive\t\t")
        else:
            name = information_dict['ASG'][0].split('-')
            final_name = '-'.join([name[0], name[1], name[2]])
            print(f"ASG\t\tActive\t\t{final_name}")

        # LBs
        if information_dict['LB'] == '':
            print(f"LB\t\tInactive\t\t")
        else:
            if len(information_dict['LB']) > 1:
                lb1 = information_dict['LB'][0].split('/')[2]
                lb2 = information_dict['LB'][1].split('/')[2]

                if len(information_dict['LB']) > 2:
                    lb3 = information_dict['LB'][2].split('/')[2]
                    print(f"LB\t\tActive\t\t{lb1}, {lb2}, {lb3}")
                else:
                    print(f"LB\t\tActive\t\t{lb1}, {lb2}")

        # EKS Nodegroup
        if information_dict['eks_nodegroup'] == '':
            print(f"NODEGROUP\tInactive\t\t")
        else:
            print(f"NODEGROUP\tActive\t\t{information_dict['eks_nodegroup']}")

        # Secrets Manager
        if not information_dict['SecretsManager']:
            print(f"SECRETS_MANAGER\tInactive\t\t")
        else:
            print(f"SECRETS_MANAGER\tActive\t\t")

        # ParameterStore
        if not information_dict['parameterstore']:
            print(f"PARAMETER_STORE\tInactive\t\t")
        else:
            print(f"PARAMETER_STORE\tActive\t\t")

        # GALAGA ZERO
        if not information_dict['galagazero']:
            print(f"GALAGA_ZERO\tInactive\t\t")

        # MSK
        if not information_dict['MSK']:
            print(f"MSK\t\tInactive\t\t")
        else:
            print(f"MSK\t\tActive\t\t{information_dict['MSK']}")

        # LOG RELAY
        if not information_dict['log-relay-asg']['Present']:
            if not information_dict['log-relay-nlb']['Present']:
                print(f"LOG-RELAY\tInactive\t\t")
        else:
            print(
                f"LOG-RELAY\tActive\t\tNLB: {information_dict['log-relay-nlb']['NLB_NAME']}, ASG: {information_dict['log-relay-asg']['ASG_NAME']}")

    else:
        print(json.dumps(information_dict, sort_keys=True, indent=4, default=str))


if __name__ == '__main__':
    asyncio.run(main())
