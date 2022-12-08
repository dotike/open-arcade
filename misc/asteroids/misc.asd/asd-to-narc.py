#!/usr/bin/env python3
"""Validate JSON file then upload to S3 bucket.

usage: asd-to-narc.py [-h] -f FILE -a ASTEROID [-b BUCKET] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  S3 File to upload
  -a ASTEROID, --asteroid ASTEROID
                        asteroid name. Something unique and useful
  -b BUCKET, --bucket BUCKET
                        Bucket to upload to. default is asd2021
  -v, --verbose         INFO information
"""

import boto3
import sys
import argparse
import json
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
import logging
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from jsonschema.exceptions import SchemaError
import os


def validatejson(jsontext, schema={}):
    """Validate JSON text against defined schema.

    :param jsontext: JSON in text format
    :param schema: JSON schema object
    :return: jsondata object
    """
    try:
        jsondata = json.loads(jsontext)
    except ValueError as err:
        logging.error('JSON error: {}'.format(err))
        sys.exit(1)
    logging.info(jsondata)

    try:
        validate(instance=jsondata, schema=schema)
    except ValidationError as errorv:
        logging.error("JSON validation error: {}".format(errorv))
        sys.exit(1)
    except SchemaError as errors:
        logging.error("JSON schema error: {}".format(errors))
        sys.exit(1)
    return jsondata


def getjsonschema(s3_resource, bucket):
    """Get JSON schema object from S3 bucket.

    :param s3_resource: S3 resource to work with
    :param bucket: Bucket to get asdschema object from
    :return: JSON object
    """
    try:
        content_object = s3_resource.Object(bucket, 'asdschema.json')
        file_content = content_object.get()['Body'].read().decode('utf-8')
    except ClientError as e:
        logging.error('AWS error: {}'.format(e))
        sys.exit(1)
    except NoCredentialsError as crede:
        logging.error('AWS error: {}'.format(crede))
        sys.exit(1)

    try:
        json_content = json.loads(file_content)
    except ValueError as err:
        logging.error('JSON schema error: {}'.format(err))
        sys.exit(1)
    logging.info(json_content)
    return json_content


def find_object(s3_client, bucket, prefix):
    """Find object from S3 bucket.

    :param s3_client: S3 client to work with
    :param bucket: Bucket to get object from
    :param prefix: search prefix
    :return: list of Objects
    """
    try:
        response = s3_client.list_objects(Bucket=bucket, Prefix=prefix)
    except ClientError as e:
        logging.error('AWS error: {}'.format(e))
        sys.exit(1)
    except NoCredentialsError as crede:
        logging.error('AWS error: {}'.format(crede))
        sys.exit(1)

    logging.info(response.get('Contents'))
    foundkeys = []
    for content in response.get('Contents', []):
        # yield content.get('Key')
        foundkeys.append(content.get('Key'))
    logging.info(foundkeys)
    return foundkeys


def delete_objects(s3_client, bucket, listofkeys):
    """Delete objects from S3 bucket.

    :param s3_client: S3 client to work with
    :param bucket: Bucket to get object from
    :param listofkeys: list of objects to delete
    :return: list of Objects
    """
    if not listofkeys:
        return False

    deleteobjects = {'Objects': []}
    for key in listofkeys:
        deleteobjects['Objects'].append({'Key': key})
    logging.info(deleteobjects)
    try:
        response = s3_client.delete_objects(Bucket=bucket, Delete=deleteobjects)
    except ClientError as e:
        logging.error('AWS error: {}'.format(e))
        sys.exit(1)
    except NoCredentialsError as crede:
        logging.error('AWS error: {}'.format(crede))
        sys.exit(1)

    logging.info(response)
    return response


def put_object(s3_client, bucket, key, data, original=None):
    """Get JSON schema object from S3 bucket.

    :param s3_client: S3 client to work with
    :param bucket: Bucket to put object into
    :param key: Name of object to put data into
    :param data: Data to put into key
    :return: S3 response
    """
    if original:
        tagline = 'original={}'.format(original)
    else:
        tagline = ''

    try:
        response = s3_client.put_object(Bucket=bucket, Key=key, Body=data, Tagging=tagline)
    except ClientError as e:
        logging.error('AWS error: {}'.format(e))
        logging.info(response)
        sys.exit(1)
    except NoCredentialsError as crede:
        logging.error('AWS error: {}'.format(crede))
        sys.exit(1)
    return response


def get_object(s3_client, bucket, key):
    """Get Data from S3 key in bucket."""
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
    except ClientError as e:
        logging.error('AWS error: {}'.format(e))
        logging.info(response)
        sys.exit(1)
    except NoCredentialsError as crede:
        logging.error('AWS error: {}'.format(crede))
        sys.exit(1)
    return response['Body'].read().decode('utf-8')


def main():
    """Parse arguments and passing them into functions."""
    s3_resource = boto3.resource('s3')
    s3_client = boto3.client("s3")

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file",
                        help="S3 File to upload", required=True)
    parser.add_argument("-a", "--asteroid",
                        help="asteroid name.  Something unique and useful", required=True)
    parser.add_argument("-b", "--bucket",
                        help="Bucket to upload to.  default is asd2021",
                        default=os.getenv('ASD_BUCKET', default="asd2021"))
    parser.add_argument("-v", "--verbose",
                        help="INFO information",
                        action="store_true")
    args = parser.parse_args()
    filename = args.file
    bucket = args.bucket
    asteroid = args.asteroid
    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    # Using UTC date radix as path for uploaded file
    # Date radix uses YYYY to keep search unique  dd/mm/yy == yy/mm/dd
    utcnow = datetime.utcnow()
    dateradix = utcnow.strftime("%Y/%m/%d/%H/%M")

    jsontext = get_object(s3_client, bucket, filename)
    logging.info(jsontext)
    # JSON schema should be stored in the bucket already
    jsonschema = getjsonschema(s3_resource, bucket)
    # Validate JSON text against JSON schema
    servicedata = validatejson(jsontext, jsonschema)
    logging.info(servicedata)

    # Create hash of json text to use as unique filename in S3
    narcid = '{}-{}'.format(asteroid, servicedata['service'])
    servicedata['service'] = 'narc-{}'.format(narcid)
    radixhash = "narc/{}.json".format(narcid)
    response = put_object(s3_client, bucket, radixhash, json.dumps(servicedata, indent=4, sort_keys=True))
    logging.info(response)
    print('{} {}'.format(bucket, radixhash))


if __name__ == "__main__":
    main()
