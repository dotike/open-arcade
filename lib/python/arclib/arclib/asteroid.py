#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
asteroid --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.1'

import boto3
import json
import logging
import os
import sys
import re
from datetime import datetime
from jsonschema import validate as jsonvalidate
from arclib import storage


class Asteroid:
    """
    A class used to represent an asteroid service.

    Class Attributes:
        ASTEROID_SCHEMA_FILE: A class variable to hold the location of the asteroid schema file.
        ASTEROID_SCHEMA: A object to hold the asteroid json schema.

    Attributes:
        name: A string of the name of the asteroid service
        version: A string of the version of the asteroid service
        metadata: A dictionary to hold the metadata with key=value
        tags: A dictionary to hold the tags with key=value
        services: A dictionary to hold asd services
    """
    ASTEROID_SCHEMA_S3_FILE = "asteroid-schema.json"
    ASTEROID_SCHEMA = None
    ASD_SCHEMA_S3_FILE = "asdschema.json"
    ASD_SCHEMA = None
    ASTEROID_ID_PATTERN = "^[a-z][a-z0-9]{3,23}$"

    @classmethod
    def set_schema(cls):
        session = boto3.session.Session()
        bucket = storage.get_account_global_bucket(session)

        cls.ASTEROID_SCHEMA = storage.s3_json_to_dict(session, bucket, cls.ASTEROID_SCHEMA_S3_FILE)
        cls.ASD_SCHEMA = storage.s3_json_to_dict(session, bucket, cls.ASD_SCHEMA_S3_FILE)

    @classmethod
    def validate(cls, obj):
        """Download Schema and Validate an object against asteroid json schema."""

        if not cls.ASTEROID_SCHEMA:
            cls.set_schema()

        try:
            jsonvalidate(instance=obj, schema=cls.ASTEROID_SCHEMA)
        except Exception as e:
            logging.error(f"Invalid asteroid json obj: {e}")
            return False
        return True

    @classmethod
    def id_validate(cls, name):
        """Validate whether name is alphanumeric with length between 4 to 16"""
        if re.match(cls.ASTEROID_ID_PATTERN, name):
            return True
        else:
            return False

    @classmethod
    def override_asd(cls, asd_json, key, value):
        node = asd_json
        path = key.split('/')

        for p in path[:-1]:
            if p.isnumeric():
                node = node[int(p)]
            else:
                if p not in node:
                    node[p] = {}
                node = node[p]

        if path[-1] not in node:
            node[path[-1]] = {}

        if isinstance(node[path[-1]], bool):
            val = True if value.lower() == "true" else False
            node[path[-1]] = val
        elif isinstance(node[path[-1]], int):
            node[path[-1]] = int(value)
        else:
            node[path[-1]] = value

        return type(node[path[-1]])

    def __init__(self, name="", version=1):
        self.user = os.getenv('USER', '')
        self.createTime = ''
        self.name = name
        self.version = version
        self.metadata = {}
        self.tags = {}
        self.services = {}
        self.namespace = name
        self.environment = 'dev'
        self.desired_state = ''
        self.narc_dict = {}

    def from_data(self, json_data):
        """Initialize an asteroid service from a json string"""
        self.name = json_data['name']
        self.version = json_data['version']
        self.metadata = json_data['metadata']
        self.tags = json_data['tags']
        self.services = json_data['services']
        self.namespace = json_data['namespace']
        self.environment = json_data['environment']
        self.desired_state = json_data['desired_state']

    def from_file(self, json_file):
        """Initialize an asteroid service from a json file."""
        with open(json_file) as f:
            data = json.load(f)
            if Asteroid.validate(data):
                self.from_data(data)
            else:
                raise Exception(f"Invalid asteroid json file {json_file}")

    def from_s3_object(self, bucket, key):
        """Initialize an asteroid service from a json file in s3 bucket."""
        session = boto3.session.Session()
        data = storage.s3_json_to_dict(session, bucket, key)
        if data == {}:
            raise Exception(f"s3 object not found: {bucket}/{key}")
        if Asteroid.validate(data):
            self.from_data(data)
        else:
            raise Exception(f"Invalid asteroid json file {bucket}/{key}")

    def add_service(self, service, location):
        """Add a asd service with service name and location. If the asteroid exists,
        only update the location of the asd service."""
        if service in self.services:
            # If service exists, only update location.
            self.services[service]['location'] = location
        else:
            # Create a new asd service.
            asd_service = {'location': location,
                           'overrides': {},
                           'config_overrides': {}
                           }
            self.services[service] = asd_service

    def add_metadata(self, key, value):
        """Add key=value pair into metadata section of asteroid service."""
        self.metadata[key] = value

    def add_tag(self, key, value):
        """Add key=value pair into tags section of asteroid service."""
        self.tags[key] = value

    def add_config_override(self, asd_json, config_override):
        """Add new key/value config data or override existing config provided by the ASD"""
        key, value = config_override.split('=', 1)

        self.services[asd_json['service']]['config_overrides'][key] = value

    def add_override(self, asd_json, override):
        """Add override{key=value} into overrides section of asd service."""
        key, value = override.split('=', 1)

        ret = Asteroid.override_asd(asd_json, key, value)

        if not Asteroid.ASD_SCHEMA:
            Asteroid.set_schema()

        try:
            jsonvalidate(instance=asd_json, schema=Asteroid.ASD_SCHEMA)
        except Exception as e:
            logging.error(f"Invalid asd json obj: {e}")
            raise e

        if ret is bool:
            val = "true" if value.lower() == "true" else "false"
            self.services[asd_json['service']]['overrides'][key] = val
        elif ret is int:
            self.services[asd_json['service']]['overrides'][key] = int(value)
        else:
            self.services[asd_json['service']]['overrides'][key] = value

    def to_json(self):
        """Dump the asteroid service to json string."""
        self.createTime = datetime.utcnow().strftime("%Y/%m/%d/%H/%M")
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)

    def to_narc(self, bucket, target_bucket, silent, asteroid_path, narc_folder='narc'):
        """Generate hydrated narc configuration."""
        session = boto3.session.Session()

        # Delete narc configurations with same asteroid id
        prefix = f"{narc_folder}/{self.name.lower()}"
        storage.delete_s3_prefix(session, target_bucket, prefix)

        self.generate_narc(bucket, asteroid_path)

        for key in self.narc_dict.keys():
            narc_item = f"{narc_folder}/{key}.json"
            json_data = json.dumps(self.narc_dict[key], sort_keys=False, indent=4)
            storage.upload_to_s3_session(session, target_bucket, json_data, narc_item)
            message = f"Narc config {key} is generated under {target_bucket}/{narc_item}"
            logging.info(message)
            if not silent:
                print(message)

    def clear_desired_state(self, arcade_name, asddata, narcid, narc_folder="narc"):
        """Set the service's 'desired_state' field to blank (the operation is completed)"""
        if 'desired_state' in asddata:
            asddata['desired_state'] = ""

        session = boto3.session.Session()
        buckets = storage.get_arcade_buckets(session, arcade_name)
        target_bucket = buckets['infrastructure']
        narc_item = f"{narc_folder}/{narcid}.json"
        json_data = json.dumps(asddata, sort_keys=False, indent=4)

        storage.upload_to_s3_session(session, target_bucket, json_data, narc_item)

    def set_restart(self, bucket, target_bucket, silent, asteroid_path, narc_folder='narc', service=None):
        """Update the 'desired_state' field of a hydrated config with 'restart'"""
        session = boto3.session.Session()

        self.generate_narc(bucket, asteroid_path, "restart")

        if service:
            # If service name is prepended with narc- remove it
            if service.startswith("narc-"):
                service = service[len("narc-"):]

            # Handle updating one single service
            if service in self.narc_dict.keys():
                # UPDATE SINGLE HYDRATED FILE FOR THAT SERVICE
                print(f"Updating service {service} within asteroid for restarting")
                narc_item = f"{narc_folder}/{service}.json"
                json_data = json.dumps(self.narc_dict[service], sort_keys=False, indent=4)
                storage.upload_to_s3_session(session, target_bucket, json_data, narc_item)
                message = f"The service {service} is scheduled for restart\ns3://{target_bucket}/{narc_item}"
                logging.info(message)
                if not silent:
                    print(message)

            else:
                print(f"The service {service} was not found in the asteroid")
                sys.exit(1)

        else:
            # UPDATE ALL HYDRATED FILES FOR ALL SERVICES
            print("Marking all services within asteroid for restarting")

            # Update all services
            for key in self.narc_dict.keys():
                narc_item = f"{narc_folder}/{key}.json"
                json_data = json.dumps(self.narc_dict[key], sort_keys=False, indent=4)
                storage.upload_to_s3_session(session, target_bucket, json_data, narc_item)
                message = f"The service {key} is scheduled for restart\ns3://{target_bucket}/{narc_item}"
                logging.info(message)
                if not silent:
                    print(message)

    def generate_narc(self, bucket, asteroid_path, desired_state=None):
        self.narc_dict = {}
        session = boto3.session.Session()

        for _, service in self.services.items():
            asd_item = service['location']
            asd_json = storage.s3_json_to_dict(session, bucket, asd_item)
            for key, value in service['overrides'].items():
                Asteroid.override_asd(asd_json, key, value)

            # Add in application_config section
            node = asd_json
            # Add ordering into hydrated config if they exist in asteroid document
            if 'order' in service:
                node['order'] = service['order']

            # Handle desired states like "restart"
            if desired_state:
                asd_json['desired_state'] = desired_state

            if 'application_config' not in node:
                node['application_config'] = {}

            consolidated_tags = {}

            if 'tags' in node:
                # Parse out tags contained in the ASD
                for key, value in node['tags'].items():
                    consolidated_tags[_k8s_safe_string(key)] = _k8s_safe_string(value)

                # Parse out tags appended to/overwritten in Asteroid
                if self.tags:
                    for key, value in self.tags.items():
                        consolidated_tags[_k8s_safe_string(key)] = _k8s_safe_string(value)

                asd_json['tags'] = consolidated_tags
            else:
                # If tags only exist within Asteroid file
                for key, value in self.tags.items():
                    consolidated_tags[_k8s_safe_string(key)] = _k8s_safe_string(value)
                asd_json['tags'] = consolidated_tags

            if not 'narc_enabled_file' in node:
                asd_json['asteroid_json'] = asteroid_path

            for key, value in service['config_overrides'].items():
                node['application_config'][key] = value

            narc_id = f"{self.name}-{asd_json['service']}"
            narc_id = narc_id.lower()
            narc_id = narc_id.replace("_", "-")

            asd_json['service'] = f"narc-{narc_id}"

            self.narc_dict[narc_id] = asd_json


# --------------------------------------------------------------------
#
# list_asteroid_objects
#
# --------------------------------------------------------------------
def list_asteroid_objects(arcade_id, inclusive=False):
    """
    starting with asterouds hydrated ocnfiguration, list all ASTEROIDS
    created AWS objects, (down into the pod and container)

    leverage existing asteroids or narc library functionality to list
    all objects

    if inclusive option is passed, walk the entire common/known child
    objects which may belong to an arcade, picking up things like:

    pods/containers in EKS not lit by ARCADE tools

    RDS instances not lit by ARCADE tools

    if no objects found, return an empty dict, (not an error)
    """

    json_str = ""

    return json_str
    #


# --------------------------------------------------------------------
#
# _k8s_safe_string
#
# --------------------------------------------------------------------
def _k8s_safe_string(str):
    """
    Args:
        str: String to make safe for kubernetes labels

    Returns: A "safe" string that only allows [0-9] [a-z] [A-Z] and _ - .
    Anything not in those groups will be converted to dash (-)
    """
    return re.sub('[^-_.0-9a-zA-Z]+', '-', re.sub('^[^0-9a-zA-Z]', 'A', str))
