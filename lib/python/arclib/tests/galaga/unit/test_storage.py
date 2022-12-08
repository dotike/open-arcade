import boto3
import pytest
from moto import mock_s3

from acrlib import storage


@mock_s3
def test_load_json(aws_credentials):
    bucket = 'mybucket'

    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket=bucket)

    key = 'folder/test.json'
    json_content = '{"key1": "val1", "key2": "val2"}'
    conn.Object(bucket, key).put(Body=json_content)

    obj = storage.load_json(bucket, key)
    assert obj['key1'] == 'val1'
    assert obj['key2'] == 'val2'

    obj = storage.load_json(bucket, 'invalid')
    assert not obj


@mock_s3
def test_key_exits(aws_credentials):
    bucket = 'mybucket'

    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket=bucket)

    key = 'folder/test.json'
    json_content = '{"key1": "val1", "key2": "val2"}'
    conn.Object(bucket, key).put(Body=json_content)

    assert storage.key_exists(bucket, key)
    assert not storage.key_exists(bucket, 'invalid')

@mock_s3
def test_get_arcade_buckets(aws_credentials):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')

    arcade = 'kind_raw.grv'

    name = arcade.replace('_', '')

    app_bucket = f'test.app.{name}'
    infra_bucket = f'test.infrastructure.{name}'
    assets_bucket = f'test.assets.{name}'

    conn.create_bucket(Bucket=app_bucket)
    conn.create_bucket(Bucket=infra_bucket)
    conn.create_bucket(Bucket=assets_bucket)

    bucket_dict = storage.get_arcade_buckets(session, arcade)
    assert bucket_dict['app'] == app_bucket
    assert bucket_dict['infrastructure'] == infra_bucket
    assert bucket_dict['assets'] == assets_bucket

    arcade = 'invalid'
    assert not storage.get_arcade_buckets(session, arcade)
