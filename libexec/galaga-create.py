#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
galaga-CRUD -- Create, Read, Update and Destroy a new Galaga layer within an Arcade
'''

# @depends: boto3, python (>=3.9)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Create, Read, Update, and Destroy a Galaga layer within an Arcade."
__usage__ = """
Galaga Create will create component services to an ARCADE based on a GALAGA JSON document.
Galaga Read will give basic status of component services in an ARCADE based on a GALAGA JSON document.
Galaga Update will update component services in an ARCADE based on a GALAGA JSON document.
Galaga Destroy will remove component services in an ARCADE based on a GALAGA JSON document.

Examples:
    arcade galaga create --arcade tmp_test.arc -p galaga/default/default.json

    arcade galaga update --arcade tmp_test.arc -p galaga/default/default.json

    arcade galaga destroy --arcade tmp_test.arc -p galaga/default/default.json
"""


import argparse
import json
import os
from pprint import pprint
from subprocess import Popen, PIPE
import subprocess
import time
import sys

import boto3

from arclib import galaga, storage, log, common
from arclib.s3_object_lock import S3ObjectLock


def main():
    """
%(prog)s - Create a new Galaga layer within an Arcade
    """
    parser = argparse.ArgumentParser(description=__description__,
                                     epilog=__usage__,
                                     prog='arcade galaga update',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-A", "--arcade", help="Arcade name", required=False)
    parser.add_argument("-p", "--path", help="GALAGA location", required=True)
    parser.add_argument("-s", "--silent", action="store_true", help="Silence all output")

    log.add_log_level_argument(parser)
    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    log.set_log_level(args.verbose)

    if not args.arcade:
        args.arcade = os.getenv('ARCADE_NAME')
        if not args.arcade:
            print("Arcade name missing, use -A/--arcade")
            parser.print_help()
            sys.exit(1)
    arcade_name = args.arcade
    os.environ["AWS_DEFAULT_REGION"] = common.get_arcade_region(arcade_name)

    tmp_dir = os.getenv("ATMP", '/tmp')

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)
    arcade_bucket = storage.get_arcade_buckets(session, arcade_name)['infrastructure']
    file_name = args.path

    calling_script = os.path.splitext(os.path.basename(__file__))
    calling_action = calling_script[0].split('-')[1]

    galaga_tags = storage.get_s3_file_tags(bucket, file_name)

    # load GALAGA JSON
    # validate JSON
    galaga_dict = storage.load_arcade_json_to_dict(bucket, file_name)
    if not galaga.validate_galaga_json(galaga_dict, "galaga"):
        print(f"{file_name} is not invalid json.")
        sys.exit(1)

    with S3ObjectLock(arcade_bucket, "Galaga", "galaga.lock", args.verbose):
        # hydrate GALAGA to GSDs then act
        component_processes = []
        for component, values in galaga_dict['components'].items():
            # GALAGA modules use ARCADE infrastructure bucket.
            hydrated_gsd_location = f"galaga/gsd/{component}.json"
            hydrated_gsd_exists = storage.key_exists(arcade_bucket, hydrated_gsd_location)
            # Update the galaga_dict to reflect the original GSD locations for longterm consistency.
            # if calling_action in ['create', 'update']:
            if hydrated_gsd_exists ^ (calling_action == 'create'):
                # Let's work on the "real" file, not the alias.
                gsd_tags = storage.get_s3_file_tags(bucket, values['location'])
                if gsd_tags.get('original'):
                    values['location'] = gsd_tags['original']
                    galaga_dict['components'][component]['location'] = gsd_tags['original']
                if not args.silent:
                    pprint(component)
                    print("----")
                    pprint(values)
                    print("----")
                # Override and Hydrate
                component_gsd_dict = storage.load_arcade_json_to_dict(bucket, values['location'])
                overridden_gsd = common.override_service_description(component_gsd_dict, values['overrides'])
                if not args.silent:
                    pprint(component_gsd_dict)
                    print("----")
                    pprint(overridden_gsd)
                    print("----")
                storage.upload_to_s3(arcade_bucket, json.dumps(overridden_gsd), hydrated_gsd_location)
            
            # Create, Destroy, Update, Read ==  calling action
            galaga_module = f"{os.environ['MYHIER']}/libexec/galaga-modules/{component}/{component}-{calling_action}"
            cmd_list = [galaga_module, "--arcade", arcade_name, "--path", hydrated_gsd_location]
            # Queue the process and store the process id for waiting.
            process = Popen(cmd_list, stdout=PIPE, stderr=PIPE)
            component_processes.append((component, process))
            # process = subprocess.run(cmd_list, stdout=PIPE, stderr=PIPE)

            # if process.poll() is not None:
            #     stdout, stderr = process.communicate()
            #     component_processes.append((component, process))

            # if not args.silent:
            #     print(component)
            #     print("----")
            #     print(process.stdout.decode())
            #     print(process.stderr.decode())
            #     print(process.returncode)
            
            # if calling_action == 'destroy' and not process.returncode:
            #     storage.delete_s3_object(arcade_bucket, f"galaga/gsd/{component}.json")
        # Wait for the queued processes to finish
        while component_processes:
            for component, process in component_processes:
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    if not args.silent:
                        print(component)
                        print("----")
                        print(stdout.decode())
                        print(stderr.decode())
                        print(process.returncode)
                    # returncode > 0 is failure.  so, not returncode defines success
                    if calling_action == 'destroy' and not process.returncode:
                        # Don't delete hydrated GSD until the destroy succeeds.
                        storage.delete_s3_object(arcade_bucket, f"galaga/gsd/{component}.json")
                    
                    component_processes.remove((component, process))
            
            time.sleep(10)

    # TODO: Handle a failure in an action.
    #  i.e. nodegroup doesn't delete from asteroids-eks component
    # Store the GALAGA used with original name and locations into infrastructure bucket
    if galaga_tags.get('original'):
        file_name = galaga_tags['original']
    if calling_action in ['create', 'update']:
        # store GALAGA with GSDs as a note to what was done, not state.
        storage.upload_to_s3(arcade_bucket, json.dumps(galaga_dict), file_name)
    if calling_action == 'destroy':
        storage.delete_s3_object(arcade_bucket, file_name)

    if not args.silent:
        pprint(calling_action)
        pprint(args)
    sys.exit(0)


if __name__ == "__main__":
    main()
