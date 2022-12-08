#-*- mode: python -*-
# -*- coding: utf-8 -*-

"""
storage --
"""

# @depends: boto3, python (>=3.7)
__author__ = 'Addepar Infrastructure Platform Tools Team <iptools@addepar.com>'
__description__ = ""
__version__ = '1.0.1'


from datetime import datetime
import hashlib
import json
import logging
from pprint import pprint

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from arclib import common


# --------------------------------------------------------------------
#
# key_exists
#
# --------------------------------------------------------------------
def key_exists(bucket: str,
               s3_file_path: str) -> bool:
    """
    Check for key in bucket.

    Args:
        bucket: s3 bucket
        s3_file_path: Full path in s3 with filename

    Returns:
        bool: key exists
    """
    s3_client = boto3.client('s3')
    try:
        s3_client.get_object(Bucket=bucket, Key=s3_file_path)
    except ClientError:
        return False

    return True


# --------------------------------------------------------------------
#
# load_json
#
# --------------------------------------------------------------------
def load_json(bucket: str,
              s3_file_path: str) -> dict:
    """
    Load json object from json file in s3 bucket

    Args:
        bucket: s3 bucket
        s3_file_path: Full path in s3 with filename

    Returns:
        dict: return the json object from json file in s3
        {}: if file is invalid or file path is invalid.
    """

    s3_client = boto3.client('s3')
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
        return json.loads(obj['Body'].read().decode('utf-8'))
    except Exception as e:
        # logging.error(f"Exception: {e}")
        return {}
    # End of load_json


# --------------------------------------------------------------------
#
# upload_to_s3
#
# --------------------------------------------------------------------
def upload_to_s3(bucket: str, data: str, key: str) -> bool:
    """Uploads a json str to s3

    Args:
        bucket: s3 bucket name
        data: a serialized json str
        key: s3 object key

    Returns:
        Bool: True (If upload was successful) False (If upload was unsuccessful)
    """
    client = boto3.client('s3')
    try:
        client.put_object(Bucket=bucket, Key=key, Body=data)
        return True
    except Exception as e:
        logging.error(f"Exception: {e}")
        return False
    # End of upload_to_s3


# --------------------------------------------------------------------
#
# upload_to_s3_session
#
# --------------------------------------------------------------------
def upload_to_s3_session(session: boto3.session.Session,
                         bucket: str,
                         data: str,
                         key: str) -> bool:
    """
    Uploads a json str to s3

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        data: a serialized json str
        key: s3 object key

    Returns:
        Bool: True (If upload was successful) False (If upload was unsuccessful)
    """
    client = session.client('s3')
    try:
        client.put_object(Bucket=bucket, Key=key, Body=data)
        return True
    except (ClientError, NoCredentialsError) as e:
        logging.error(f'AWS error: {e}')
        return False
    # End of upload_to_s3_session


# --------------------------------------------------------------------
#
# get_arcade_buckets
#
# --------------------------------------------------------------------
def get_arcade_buckets(session: boto3.session.Session,
                       arcade: str) -> dict:
    """
    Return the arcade buckets as a dictionary.

    Args:
        session: A boto3 session for accessing client and resource
        arcade: The name of arcade

    Returns:
        A dictionary with key(app, infrastructure, assets): value (bucket name)
    """
    arcade = arcade.replace('_', '')
    s3_client = session.client('s3')

    bucket_dict = {}
    try:
        buckets = s3_client.list_buckets()
    except (ClientError, NoCredentialsError) as e:
        logging.error(f"AWS Error: {e}")
        return {}

    for bucket in buckets['Buckets']:
        if f"{arcade}" in bucket['Name']:
            bucket_dict[bucket['Name'].split('.')[-3]] = bucket['Name']

    return bucket_dict
    # End of get_arcade_bucket


# --------------------------------------------------------------------
#
# get_account_global_bucket
#
# --------------------------------------------------------------------
def get_account_global_bucket(session: boto3.session.Session) -> str:
    """
    Get account global s3 bucket.

    If the bucket does not exits, create a new one

    Args:
        session: A boto3 session for accessing client and resource

    Returns:
        the account global s3 bucket name

    """
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity().get('Account')
    account_hash = hashlib.md5(account_id.encode('utf-8')).hexdigest()
    bucket_name = f"asd-{account_hash}"

    resource = session.resource('s3')
    bucket = resource.Bucket(bucket_name)

    if not bucket.creation_date:
        resource.create_bucket(Bucket=bucket_name,
                               CreateBucketConfiguration={'LocationConstraint': session.region_name})

    return bucket_name
    # End of get_account_global_bucket


# --------------------------------------------------------------------
#
# s3_file_timestamp
#
# --------------------------------------------------------------------
def s3_file_timestamp(session: boto3.session.Session,
                      bucket: str,
                      s3_file_path: str):
    """
    Returns Timestamp for a file in S3

    Args:
        session (boto3.session.Session): [Boto3 Session]
        bucket (str): [Name of the S3 Bucket]
        s3_file_path (str): [S3 file path]

    Returns:
        [type]: [description]
    """
    s3_client = session.client('s3')
    obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
    date = obj['LastModified']

    return date.strftime('%Y-%m-%d %H:%M:%S')
    # End of s3_file_timestamp


# --------------------------------------------------------------------
#
# upload_asteroid_json
#
# --------------------------------------------------------------------
def upload_asteroid_json(session: boto3.session.Session,
                         bucket: str,
                         prefix: str,
                         name: str,
                         version: str,
                         data: str,
                         silent: bool,
                         tagpath='') -> str:
    """
    Upload asd/asteroid json to s3. Always add a new s3 key and
    update latest key to the new data.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        prefix: prefix of the s3 key ('asd' or 'asteroid')
        name: asd service or asteroid name
        version: version str
        data: a serialized json str
        silent: boolean representing if -s flag is provided
        tagpath(optional): a predefined (tag) path where it should be stored
            (e.g.: 'raw_egg/asteroid-name/service-name' => 'asd/raw_egg/asteroid-name/service-name.json')
            Strings containing 'latest' are not allowed.

    Returns:
        the s3 key of radix hash version or empty string

    """

    # Bail out if 'latest' was anywhere in the tagpath.
    if tagpath and not tagpath.find('latest') == -1:
        # We don't like the string 'latest' at all!!!
        logging.error("Tags may not include 'latest'!")
        return ''

    # Ensure tagpath doesn't already contain the suffix '.json'. We add it later.
    tagpath = tagpath.removesuffix('.json')

    date_radix = datetime.utcnow().strftime("%Y/%m/%d/%H/%M")
    filename = f"{name}.json"
    hash_json = hashlib.md5(str(filename).encode('utf-8')).hexdigest()
    radix_hash = f"{prefix}/{name}/{version}/{date_radix}/{hash_json}.json"

    new_version = upload_to_s3_session(session, bucket, data, radix_hash)

    # If the optional tagpath was supplied, upload to this location too and add a tag called
    # 'original' containing the radix_hash location.
    tag_version = False
    if tagpath:
        tagline = f"original={radix_hash}"
        radix_hash_tagged = f'{prefix}/{tagpath}.json'
        tag_version = upload_to_s3_session(session, bucket, data, radix_hash_tagged)
        if not tag_version:
            return ''
        # Tag the taggpath with radix_hash.
        latest_tagged = tag_s3_file(bucket, radix_hash_tagged, tagline)

    if new_version:
        if not silent:
            print(f'{bucket} {radix_hash}')
            if tag_version:
                print(f'{bucket} {radix_hash_tagged}')
        return radix_hash
    else:
        return ''
    # End of upload_asteroid_json


# --------------------------------------------------------------------
#
# find_s3_keys
#
# --------------------------------------------------------------------
def find_s3_keys(session: boto3.session.Session,
                 bucket: str,
                 prefix: str) -> list:
    """
    Find objects from s3 bucket

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        prefix: s3 key prefix

    Returns:
        a list of keys matching prefix

    """
    try:
        s3_client = session.client('s3')
        response = s3_client.list_objects(Bucket=bucket, Prefix=prefix)
        output = []
        for content in response.get('Contents', []):
            output.append(content.get('Key'))
        return output
    except (ClientError, NoCredentialsError) as e:
        logging.info(f'AWS error: {e} for key: {prefix}')
        return []
    # End of find_s3_keys


# --------------------------------------------------------------------
#
# s3_object_to_str
#
# --------------------------------------------------------------------
def s3_object_to_str(session: boto3.session.Session, bucket: str, s3_file_path: str) -> str:
    """
    Load json file in s3 and return as a dictionary.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: bucket name
        s3_file_path: Full path in S3 with filename

    Returns:
        dict: return the dictionary from json file in s3, or empty dictionary
    """
    s3_client = session.client('s3')
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
        return str(obj['Body'].read().decode('utf-8'))
    except ClientError as c_e:
        logging.info(f"Client error: {c_e} for key: {s3_file_path}")
        return ""


# --------------------------------------------------------------------
#
# s3_json_to_dict
#
# --------------------------------------------------------------------
def s3_json_to_dict(session: boto3.session.Session,
                    bucket: str,
                    s3_file_path: str) -> dict:
    """
    Load json file in s3 and return as a dictionary.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: bucket name
        s3_file_path: Full path in S3 with filename

    Returns:
        dict: return the dictionary from json file in s3, or empty dictionary
    """
    s3_client = session.client('s3')
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
        return json.loads(obj['Body'].read())
    except Exception as e:
        logging.info(f"Exception: {e} for key: {s3_file_path}")
        return {}
    # End of s3_json_to_dict


# --------------------------------------------------------------------
#
# delete_s3_prefix
#
# --------------------------------------------------------------------
def delete_s3_prefix(session: boto3.session.Session,
                     bucket: str,
                     prefix: str) -> None:
    """
    Delete keys in s3 with prefix.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        prefix: s3 key prefix

    Returns:
        None

    """
    bucket = session.resource('s3').Bucket(bucket)
    bucket.objects.filter(Prefix=prefix).delete()
    # End of delete_s3_prefix


# --------------------------------------------------------------------
#
# delete_s3_object
#
# --------------------------------------------------------------------
def delete_s3_object(bucket: str, key: str):
    """
    Delete a key in s3 with prefix.

    Args:
        bucket: s3 bucket name
        prefix: s3 key prefix

    Returns:
        None
    """
    s3_client = boto3.client('s3')
    s3_client.delete_object(Bucket=bucket, Key=key)
    # End of delete_s3_object


# --------------------------------------------------------------------
#
# download_s3_file
#
# --------------------------------------------------------------------
def download_s3_file(session: boto3.session.Session,
                     bucket: str,
                     key: str,
                     filename: str) -> None:
    """
    Download s3 file to local.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        key: s3 key
        filename: local file name

    Returns:
        None
    """

    session.resource('s3').Bucket(bucket).download_file(key, filename)

# --------------------------------------------------------------------
#
# upload_s3_file
#
# --------------------------------------------------------------------
def upload_s3_file(session: boto3.session.Session,
                     bucket: str,
                     key: str,
                     filename: str) -> None:
    """
    Upload local file to s3.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        key: s3 key
        filename: local file name

    Returns:
        None
    """

    # session.resource('s3').Bucket(bucket).upload_file(key, filename)
    s3_client = session.client('s3')

    with open(filename, 'rb') as data:
        s3_client.upload_fileobj(data, bucket, key)


# --------------------------------------------------------------------
#
# load_arcade_json_to_dict
#
# --------------------------------------------------------------------
def load_arcade_json_to_dict(bucket: str,
                             s3_file_path: str) -> dict:
    """
    Load json file from s3 and return as a dictionary.

    Args:
        bucket: bucket name
        s3_file_path: Full path in S3 with filename

    Returns:
        dict: return the dictionary from json file in s3, or empty dictionary
    """
    s3_client = boto3.client('s3')
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
        return json.loads(obj['Body'].read())
    except (ClientError, NoCredentialsError):
        return {}


# --------------------------------------------------------------------
#
# load_json_file_to_dict
#
# --------------------------------------------------------------------
def load_json_file_to_dict(file_name: str) -> dict:
    """
    Load json file from OS and return as a dictionary.

    Args:
        file_name: The full path of the file.

    Returns:
        dict: return the dictionary from json file or empty dictionary
    """
    try:
        with open(file_name, "r", encoding="utf-8") as file_object:
            return json.load(file_object)
    except OSError:
        # print(f"Unable to open {path}: {o_e}", file=sys.stderr)
        return {}


# --------------------------------------------------------------------
#
# read_file
#
# --------------------------------------------------------------------
def read_file(file_name: str) -> str:
    """
    Load file from OS and return as a string.

    Args:
        file_name: The full path of the file.

    Returns:
        str: return the text from a file or empty string.
    """
    try:
        with open(file_name, "r", encoding="utf-8") as file_object:
            return file_object.read()
    except OSError:
        # print(f"Unable to open {path}: {o_e}", file=sys.stderr)
        return ""


# --------------------------------------------------------------------
#
# tag_s3_file
#
# --------------------------------------------------------------------
def tag_s3_file(bucket: str, key: str, tag: str) -> bool:
    """Tag a S3 key.

    Args:
        bucket: s3 bucket name
        key: s3 object key
        tag: The tag to apply to the key in URL query format.
                i.e. key=value

    Returns:
        Bool: True (If tagging was successful) False (If tagging was unsuccessful)
    """
    s3_client = boto3.client('s3')
    tag_components = tag.split('=')
    tag_set = {'TagSet': [{'Key': tag_components[0], 'Value': tag_components[1]}]}
    try:
        s3_client.put_object_tagging( Bucket=bucket, Key=key, Tagging=tag_set)
        return True
    except ClientError:
        return False


# --------------------------------------------------------------------
#
# get_s3_file_tags
#
# --------------------------------------------------------------------
def get_s3_file_tags(bucket: str, key: str) -> dict:
    """Get the tags from a S3 key.

    Args:
        bucket: s3 bucket name
        key: s3 object key

    Returns:
        dict: Dictionary of Tags in Sane format.
                i.e. {'key': 'value', 'key': 'value'}
    """
    s3_client = boto3.client('s3')
    try:
        response = s3_client.get_object_tagging(Bucket=bucket, Key=key)
        return common.aws_tags_dict(response.get('TagSet'))
    except ClientError:
        return {}
