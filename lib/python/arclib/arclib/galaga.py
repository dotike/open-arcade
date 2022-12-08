#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
galaga --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.0'


import asyncio
from datetime import datetime
import graphlib
import json
import logging
import os
import sys

import boto3
from botocore.exceptions import ClientError
import jsonschema
from jsonschema import validate

from arclib.s3_object_lock import S3ObjectLock
from arclib import grv
from arclib import storage


# --------------------------------------------------------------------
#
# list_galaga_objects
#
# --------------------------------------------------------------------
def list_galaga_objects(arcade_id, inclusive=False):
    """
    starting with galaga hydrated configuration, list all GRAVITAR
    created AWS objects

    If 'inclusive' option passed, walk common/known child objects
    which may belong to an ARCADE at the GALAGA layer (e.g. GALAGA
    zero type stuff)

    leave a clear 'stub' in this routine to add critical one-off
    things we may want to add later

    try to use existing galaga library routines where applicable

    if no objects found, return an empty dict (not error)
    """

    json_str = ""

    return json_str
    #


def validate_galaga_json(galaga_data: dict,
                         galaga_type: str) -> bool:
    """
    Validate a dictionary against galaga json schema.

    Args:
        galaga_data - JSON data as a dictionary
        galaga_type - gsd or galaga

    Returns:
        bool - true if dictionary validates against schema
    """
    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)
    if galaga_type == 'gsd':
        schema_file = 'gsdschema.json'
    else:
        schema_file = 'galaga-schema.json'
    galaga_schema = storage.load_arcade_json_to_dict(bucket, schema_file)

    try:
        jsonschema.validate(instance=galaga_data, schema=galaga_schema)
    except jsonschema.exceptions.ValidationError:
        return False
    return True


def add_component(galaga_dict, component, location) -> dict:
    """Add a gsd component with component name and location. If the component exists,
    only update the location of the gsd component."""
    if component in galaga_dict['components']:
        # If component exists, only update location.
        galaga_dict['components'][component]['location'] = location
    else:
        # Create a new gsd component.
        gsd_component = {'location': location,
                         'overrides': {}
                         }
        galaga_dict['components'][component] = gsd_component

    return galaga_dict


def remove_component(galaga_dict, component, location) -> dict:
    """Remove a gsd component with component name and location. If the component exists,
    only update the location of the gsd component."""
    if component in galaga_dict['components']:
        # If component exists, only update location.
        galaga_dict['components'].pop(component)
    # else:
    #     # Create a new gsd component.
    #     gsd_component = {'location': location,
    #                      'overrides': {}
    #                      }
    #     galaga_dict['components'][component] = gsd_component

    return galaga_dict


def add_override(galaga_dict, gsd_json, override) -> dict:
    """Add override{key=value} into overrides section of gsd component"""
    pair = override.split('=')
    key = pair[0].split("/")
    node = gsd_json
    # Validate the overrides
    try:
        # Search the key in asd json object.
        for k in key:
            if k.isnumeric():
                node = node[int(k)]
            else:
                node = node[k]

        # Add {key: value} to the override dictionary of gsd component.
        # Only provide option to override string or integer.
        if isinstance(node, str):
            galaga_dict['components'][gsd_json['name']]['overrides'][pair[0]] = pair[1]
        elif isinstance(node, int):
            galaga_dict['components'][gsd_json['name']]['overrides'][pair[0]] = int(pair[1])
        else:
            raise ValueError(f"The key {pair[0]} is not overridable.")
        return galaga_dict
    except Exception as err:
        # Ignore the override if it is invalid.
        logging.error(err)
        logging.error(f"Invalid override option for component {gsd_json['components']} with key={pair[0]}.")


def remove_override(galaga_dict, gsd_json, override) -> dict:
    """Add override{key=value} into overrides section of gsd component"""
    pair = override.split('=')
    key = pair[0].split("/")
    node = gsd_json
    # Validate the overrides
    try:
        # Search the key in asd json object.
        for k in key:
            if k.isnumeric():
                node = node[int(k)]
            else:
                node = node[k]

        # Add {key: value} to the override dictionary of gsd component.
        # Only provide option to override string or integer.
        galaga_dict['components'][gsd_json['name']]['overrides'].pop(pair[0])
    except Exception as err:
        # Ignore the override if it is invalid.
        logging.info(err)
        logging.info(f"Invalid override option for component with key={pair[0]}.")

    return galaga_dict
