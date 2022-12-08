#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

'''
inventory --

See Jira ticket IPTOOLS-452 and git branch josef-IPTOOLS-452-rebased

'''

# @depends: boto3, python (>=3.8)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = "This tool generates an inventory of all AWS resources assigned to a arcade."
__usage__ = "man inventory"
__version__ = '0.2'

import argparse
import os
import sys
import json

from arclib import common
from arclib import inventory as inv


# --------------------------------------------------------------------
#
# main
#
# --------------------------------------------------------------------
def main():
    """
    The main function that drives this tool
    """

    rs_defines = common.ReturnStatus()
    common_dict = {}
    common_dict['RS'] = rs_defines
    # r_dict = common.gen_return_dict()

    # The minimum version of python we support is 3.8
    min_python_version = (3, 8)
    if sys.version_info < min_python_version:
        print("Python %s.%s or later is required.\n" % min_python_version)
        sys.exit(rs_defines.NOT_OK)

    tool_name = os.path.basename(__file__)
    version = __version__

    parser = argparse.ArgumentParser(description=__description__,
                                     epilog=__usage__,
                                     prog='arcade inventory',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     add_help=False)

    parser.add_argument('-A', '--name', help='Arcade name (required)')

    parser.add_argument('-n', '--arcade', help='Arcade layer',
                        action='store_true')

    parser.add_argument('-a', '--asteroid', help='Asteroid layer (default)',
                        action='store_true')

    parser.add_argument('-g', '--galaga', help='Galaga layer',
                        action='store_true')

    parser.add_argument('-G', '--gravitar', help='Gravitar layer',
                        action='store_true')

    parser.add_argument('-i', '--inclusive', help='Find everything',
                        action='store_true')

    parser.add_argument('-j', '--json', help='Output json unformatted',
                        action='store_true')

    parser.add_argument('-J', '--JSON', help='Output human readable json. (default)',
                        action='store_true')

    parser.add_argument('-o', '--output', help='Write output to a file',
                        action='store_true')

    parser.add_argument('-V', '--version', action='store_true',
                        help='Output version')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    parser.add_argument('-h', '--help', action='store_true',
                        help='Verbose Help')

    args = parser.parse_args()

    # Validate that aws credentials are valid
    common.validate_aws_creds()

    # Spit out the version
    if args.version:
        print(f"{tool_name} - Version: {version}")
        sys.exit(rs_defines.OK)

    # Verbose Help
    if args.help:
        print_verbose_help()
        sys.exit(rs_defines.OK)

    # Do we have an arcade name even if the TLD is missing
    if not args.name:
        args.name = os.getenv('ARCADE_NAME', "")
        if not args.name:
            print(f"\n{tool_name}: ERROR - Arcade name was not provided. Try again.\n")
            sys.exit(rs_defines.NOT_OK)
    if '.arc' not in args.name:
        arcade_name = f"{args.name}.arc"
    else:
        arcade_name = args.name

    # Which output format selected ?
    # If none selected we force the machine readable version
    if args.json is False and args.JSON is False:
        args.JSON = True

    # Did we select a layer ?
    # If not we exit with an error
    if (not args.asteroid and not args.arcade and
            not args.galaga and not args.gravitar):
        args.asteroid = True

    # Here we list the select the layers
    if args.arcade:
        common_dict = list_arcade_objects(arcade_name, args.inclusive)

    if args.asteroid:
        common_dict = list_asteroid_objects(arcade_name, args.inclusive)

    if args.galaga:
        common_dict = list_galaga_objects(arcade_name, args.inclusive)

    if args.gravitar:
        common_dict = list_grv_objects(arcade_name, args.inclusive)

    # We have got all the data now format and output
    if common_dict['status'] == rs_defines.OK:
        inv_dict = inv.build_inventory_dict(common_dict)
        inventory_format_and_output(inv_dict, args)
    elif common_dict['status'] == rs_defines.NOT_YET:
        print(f"\nAn inventory of the {common_dict['layer']} layer not available yet. Stay tuned.\n")

    sys.exit(rs_defines.OK)
    # End of main


# --------------------------------------------------------------------
#
# list_grv_objects
#
# --------------------------------------------------------------------
def list_grv_objects(arcade_name, inclusive=False):
    """
    Generate an inventory of AWS resources in the gravitar layer
    of an arcade.

    Args:
        arcade_name: The name, as a string, of the arcade to be
        queried.

        inclusive: A boolean denoting how much of the AWS resources
        to be inventoried.

    Returns:
        A dict containg the inventory.

    """

    return inv.get_resource_info(arcade_name, inclusive, 'gravitar')

    # End of list_grv_objects


# --------------------------------------------------------------------
#
# list_galaga_objects
#
# --------------------------------------------------------------------
def list_galaga_objects(arcade_name, inclusive=False):
    """
    Generate an inventory of AWS resources in the galaga layer
    of an arcade.

    Args:
        arcade_name: The name, as a string, of the arcade to be
        queried.

        inclusive: A boolean denoting how much of the AWS resources
        to be inventoried.

    Returns:
        A dict containg the inventory.
    """

    return inv.get_resource_info(arcade_name, inclusive, 'galaga')

    # End of list_galaga_objects


# --------------------------------------------------------------------
#
# list_asteroid_objects
#
# --------------------------------------------------------------------
def list_asteroid_objects(arcade_name, inclusive=False):
    """
    Generate an inventory of AWS resources in the asteroid layer
    of an arcade.

    Args:
        arcade_name: The name, as a string, of the arcade to be
        queried.

        inclusive: A boolean denoting how much of the AWS resources
        to be inventoried.

    Returns:
        A dict containg the inventory.
    """

    return inv.get_resource_info(arcade_name, inclusive, 'asteroid')

    # End of list_asteroid_objects


# --------------------------------------------------------------------
#
# list_arcade_objects
#
# --------------------------------------------------------------------
def list_arcade_objects(arcade_name, inclusive=False):
    """
    Generate an inventory of AWS resources in the arcade layer
    of an arcade.

    Args:
        arcade_name: The name, as a string, of the arcade to be
        queried.

        inclusive: A boolean denoting how much of the AWS resources
        to be inventoried.

    Returns:
        A dict containg the inventory.
    """

    return inv.get_resource_info(arcade_name, inclusive, 'arcade')

    # End of list_arcade_objects


# ---------------------------------------------------------
#
# inventory_format_and_output
#
# ---------------------------------------------------------
def inventory_format_and_output(in_dict: dict, args: dict) -> dict:
    """
    Output the conents of the inventory dict as a json string
    either to stdout or to a file.

    This goes in common.py

    Args:
        in_dict: The dictonary of values to be formated and printed

        args: The dictonary of command line options

    Returns:
        A dictonary containing the status, path that was written to
        if the output option was specified, and a msg to be printed.

    """

    output_string = ""
    r_dict = common.gen_return_dict("Formatting output")

    arcade_name = in_dict['arcade_name']

    if args.JSON:
        output_string = json.dumps(in_dict, indent=4, sort_keys=True, default=str)
    elif args.json:
        output_string = json.dumps(in_dict, sort_keys=True, default=str)

    if args.output:
        output_dir = which_tmp_dir()
        layer = in_dict['layer']

        if in_dict['inclusive'] is True:
            output_file = f"{output_dir}/{arcade_name}-{layer}-inclusive-inventory.json"
        else:
            output_file = f"{output_dir}/{arcade_name}-{layer}-inventory.json"

        with open(output_file, 'w') as file_handle:
            file_handle.write(output_string)

        msg = f"Wrote inventory manifest to {output_file}"
        print(msg)
        r_dict['msg'] = msg
    else:
        r_dict['msg'] = 'Output to stdout'
        print(output_string)

    return r_dict
    # End of inventory_format_and_output


# ---------------------------------------------------------
#
# which_tmp_dir
#
# ---------------------------------------------------------
def which_tmp_dir():
    """
    This function determines which tmp dir to use with
    a preference for ATMP

    Args:
        None

    Returns:
        a_tmp_dir: A FQP to a temp directory
    """

    a_tmp_dir = ''

    atmp = os.getenv('ATMP')
    if atmp is None:
        home_dir = os.getenv('HOME')
        atmp = f"{home_dir}/tmp/arcade"
        if not os.path.exists(atmp):
            os.makedirs(atmp)

    a_tmp_dir = atmp

    # env_list = ['ATMP', 'TMPDIR', 'TMP_DIR']
    # path_list = ['/usr/tmp', '/tmp', '/usr/local/tmp', '/usr/local/site/tmp']

    # tmp_var = select_path(env_list, path_list, default_tmp_dir)

    # if tmp_var == default_tmp_dir:
    #    if tmp_var is not None:
    #        this_tmp_dir = tmp_var
    #    else:
    #        this_tmp_dir = default_tmp_dir
    # else:
    #    this_tmp_dir = tmp_var

    return a_tmp_dir
    # End of which_tmp_dir


# ---------------------------------------------------------
#
# which_log_dir
#
# ---------------------------------------------------------
def which_log_dir():
    """
    This is a place holder for a future function that
    will select the direcory to be used for logging.

    Args:
        TBD

    Returns:
        TBD
    """

    default_log_dir = ''
    this_log_dir = ''

    env_list = []
    path_list = []

    tmp_var = select_path(env_list, path_list, default_log_dir)
    this_log_dir = tmp_var

    return this_log_dir
    # End of which_tmp_dir


# ---------------------------------------------------------
#
# select_path
#
# ---------------------------------------------------------
def select_path(env_list, path_list, default_value):
    """
    This is a place holder for a future function that
    will select the direcory to be used


    Args:
        TBD

    Returns:
        TBD
    """

    value_found = False
    selected_value = ''

    # Search the env list
    for entry in env_list:
        tmp_var = os.getenv(entry)
        if tmp_var is not None:
            value_found = True
            selected_value = tmp_var
            break

    # Nothing in the env list, try the path list
    if value_found is False:
        for entry in path_list:
            tmp_var = os.path.exists(entry)
            if tmp_var is not None:
                value_found = True
                selected_value = tmp_var
                break

    # OK, still not found going with the default value
    if value_found is False:
        selected_value = default_value

    return selected_value
    # End of select_path


# --------------------------------------------------------------------
#
# print_verebose_help
#
# --------------------------------------------------------------------
def print_verbose_help():
    r_dict = common.gen_return_dict('In print_verbose_help')

    myhier = os.getenv('MYHIER')
    if myhier is None:
        print("ERROR: MYHIER not set. Try again")
        sys.exit(1)

    verbose_help = f"{myhier}/etc/inventory-verbose-help.txt"

    help_msg = ''

    if os.path.exists(verbose_help):
        with open(verbose_help, 'r') as file_handle:
            help_msg = file_handle.read()
    else:
        print(f"ERROR: {verbose_help} NOT found.")
        sys.exit(1)

    print(help_msg)

    return r_dict
    # End of print_verbose_help


# --------------------------------------------------------------------
#
# Entry point
#
# --------------------------------------------------------------------
if __name__ == '__main__':
    main()
    # End of entry point
