import boto3
import pytest
import json
from moto import mock_s3

from _storage import Galaga_Storage

g_g = __import__('gsd-get')


@mock_s3
def test_printstdout(aws_credentials, gsd_schema):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    a_s = Galaga_Storage(bucket='mybucket')
    with open(gsd_schema) as fp:
        jsontext = json.load(fp)
        data = json.dumps(jsontext)
    key = '/tmp/gsdschema.json'
    a_s.upload(data, key)

    s3_client = boto3.client('s3')
    bucket = 'mybucket'
    filename = '/tmp/gsdschema.json'
    assert g_g.printstdout(s3_client, bucket, filename)
    bucket = 'wrongbucket'
    assert not g_g.printstdout(s3_client, bucket, filename)


@mock_s3
def test_gsd_get(monkeypatch, aws_credentials):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    g_s = Galaga_Storage(bucket='mybucket')
    key = 'tmp/data.json'
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
    g_s.upload(data, f"galaga/{key}")

    s3_client = boto3.client('s3')
    monkeypatch.setenv('GSD_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest", "-f", key])
    g_g.main()

    bucket = conn.Bucket('mybucket')

    objects = list(bucket.objects.filter(Prefix=''))
    assert len(objects) == 1
    assert 'galaga/tmp/data.json' in objects[0].key
