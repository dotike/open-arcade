import boto3
import json
from moto import mock_s3
import yaml

from _storage import Galaga_Storage

g_u = __import__('gsd-upload')


def test_validatejson():
    data = {
        "id": 1,
        "name": "test",
        "dimensions": {
            "length": 7.0,
            "width": 12.0,
            "height": 9.5
        },
        "location": {
            "latitude": 'some-latitude',
            "longitude": 'some-longitude'
        }
    }
    jsontext = json.dumps(data)
    schema = {}
    assert g_u.validatejson(jsontext, schema)
    data = dict(
        A='a',
        B=dict(
            C='c',
            D='d',
            E='e',
        )
    )
    jsontext = yaml.dump(data, default_flow_style=False)
    assert not g_u.validatejson(jsontext, schema)


@mock_s3
def test_getjsonschema(aws_credentials, gsd_schema):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    a_s = Galaga_Storage(bucket='mybucket')
    with open(gsd_schema) as fp:
        jsontext = json.load(fp)
        data = json.dumps(jsontext)
    key = 'galaga/gsdschema.json'
    a_s.upload(data, key)

    bucket = 'mybucket'
    s3_resource = boto3.resource('s3')
    assert g_u.getjsonschema(s3_resource, bucket)
    bucket = 'wrongbucket'
    assert not g_u.getjsonschema(s3_resource, bucket)


@mock_s3
def test_find_object(aws_credentials, gsd_schema):
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
    prefix = '/tmp/'
    assert g_u.find_object(s3_client, bucket, prefix)
    prefix = '/wrongprefix/'
    assert not g_u.find_object(s3_client, bucket, prefix)


@mock_s3
def test_delete_objects(aws_credentials, gsd_schema):
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
    listofkeys = ['/tmp/gsdschema.json']
    assert g_u.delete_objects(s3_client, bucket, listofkeys)
    bucket = 'wrongbucket'
    assert not g_u.delete_objects(s3_client, bucket, listofkeys)


@mock_s3
def test_put_object(aws_credentials):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    a_s = Galaga_Storage(bucket='mybucket')
    key = '/tmp/new.json'
    data = b'{"firstName":"test", "lastName":"testing"}'
    a_s.upload(data, key)

    s3_client = boto3.client('s3')
    bucket = 'mybucket'
    data = b'{"firstName":"new", "lastName":"test"}'
    assert g_u.put_object(s3_client, bucket, key, data)


@mock_s3
def test_gsd_upload(monkeypatch, aws_credentials, gsd_schema, gsd_alb):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    a_s = Galaga_Storage(bucket='mybucket')
    key = 'galaga/gsdschema.json'
    with open(gsd_schema) as fp:
        jsonschema = json.load(fp)
        data = json.dumps(jsonschema)
    a_s.upload(data, key)

    monkeypatch.setenv('GSD_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_alb])
    g_u.main()

    bucket = conn.Bucket('mybucket')

    objects = list(bucket.objects.filter(Prefix=''))
    assert len(objects) == 3
    assert 'galaga/gsdschema.json' in objects[2].key
