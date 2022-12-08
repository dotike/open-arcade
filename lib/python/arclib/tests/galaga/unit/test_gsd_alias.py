import boto3
import pytest
import json
from moto import mock_s3

from _storage import Galaga_Storage

g_a = __import__('gsd-alias')

@mock_s3
def test_copy_object(aws_credentials, gsd_schema):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    g_s = Galaga_Storage(bucket='mybucket')
    with open(gsd_schema) as fp:
        jsontext = json.load(fp)
        data = json.dumps(jsontext)

    key = '/tmp/gsdschema.json'
    g_s.upload(data, key)

    s3_client = boto3.client('s3')
    bucket = 'mybucket'
    source = '/tmp/gsdschema.json'
    dest = '/tmp/new_gsdschema.json'
    assert g_a.copy_object(s3_client, bucket, source, dest)
    bucket = 'wrongbucket'
    assert not g_a.copy_object(s3_client, bucket, source, dest)
  
@mock_s3
def test_gsd_alias(aws_credentials, monkeypatch):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    g_s = Galaga_Storage(bucket='mybucket')
    key = '/tmp/data.json'
    jsontext = {
        "id": 1,
        "name": "test",
        "dimensions": {
            "length": 7.0,
            "width": 12.0,
            "height": 9.5
        },
        "location": {
            "latitude": "some-latitude",
            "longitude": "some-longitude"
        }
    }
    data = json.dumps(jsontext)
    g_s.upload(data, key)

    s3_client = boto3.client('s3')
    tag = '/tmp/newdata.json'
    monkeypatch.setenv('GSD_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest", "-f", key, "-t", tag])
    g_a.main()

    bucket = conn.Bucket('mybucket')

    objects = list(bucket.objects.filter(Prefix=''))
    assert len(objects) == 2
    assert '/tmp/newdata.json' in objects[1].key