#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
asteroid-create -- Create a new Asteroid json document on the local machine.
'''

# @depends: boto3, python (>=3.7)
__version__ = '0.1'
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "Creates a new dehydrated asteroid service description file on your local computer."
__usage__ = """
Asteroid Create, will create a Asteroid Service Description file locally in the ~/tmp/arcade directory.
This JSON file will moreless be empty with predefined keys and some values.
You will need to use `arcade asteroid add` to add Asteroid Service Descriptions to the Asteroid Service Description file.
This is a dehydrated asteroid service description.

Examples:
    arcade asteroid create -a testdroid
    Asteroid testdroid is created under /Users/some_user/tmp/arcade/testdroid.json

    arcade asteroid create -a testdroid --version 2 -m somekey=somevalue

    arcade asteroid create -a testdroid --version 2 -t sometag=somevalue

"""

import argparse
import os, sys

from arclib.asteroid import Asteroid
from arclib import log


def main():
    """
    This function takes no arguments.
    This function works with argparse to parse command line options at the command line. 
    If no options are passsed then the method will not execute.
    """
    parser = argparse.ArgumentParser(description=__description__, epilog=__usage__, prog='arcade asteroid create', formatter_class=argparse.RawTextHelpFormatter)
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument("-a", "--asteroid", help="Required, The name of the asteroid being created. This defines the name of the asteroid", required=True)
    
    parser.add_argument("--version", help="Optional, gives a version to the non-hydrated asteroids service definition file. Defaults to version 1", default="1")
    
    parser.add_argument("-m", "--metadata", help="Optional, This is metadata for the Asteroid Service Directory, key=value pair.", action='append')
    
    parser.add_argument("-t", "--tags", help="Optional, This is a key value pair for kubernetes labels", action='append')
    
    
    args = parser.parse_args()

    tmp_dir = os.getenv("ATMP", '/tmp')

    metadata = args.metadata
        
    tags = args.tags
    
    if not Asteroid.id_validate(args.asteroid):
        print(f"Asteroid id needs to conform to {Asteroid.ASTEROID_ID_PATTERN}", file=sys.stdout)
        sys.exit(1)

    name = args.asteroid
    version = int(args.version)

    filename = f"{tmp_dir}/{name}.json"

    if os.path.exists(filename):
        print(f"Asteroid {name} already exists under {filename}")
        sys.exit(1)

    asteroid = Asteroid(name, version)

    if metadata:
        for meta in metadata:
            pair = meta.split('=')
            asteroid.add_metadata(pair[0], pair[1])

    if tags:
        for tag in tags:
            pair = tag.split('=')
            asteroid.add_tag(pair[0], pair[1])

    with open(filename, 'w') as json_file:
        json_file.write(asteroid.to_json())

    print(f"Asteroid {name} is created under {filename}")


if __name__ == "__main__":
    main()
