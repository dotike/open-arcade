import boto3
import json
from moto import mock_s3, mock_sts

from arclib import storage

asd_alias = __import__('asd-alias')


@mock_s3
@mock_sts
def test_asd_alias(aws_credentials, monkeypatch):
    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

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
    storage.upload_to_s3(session, bucket_name, data, key)

    tag = '/tmp/newdata.json'
    monkeypatch.setattr("sys.argv", ["pytest", "-f", key, "-t", tag])
    asd_alias.main()

    bucket = session.resource('s3').Bucket(bucket_name)

    objects = list(bucket.objects.filter(Prefix=''))
    assert len(objects) == 2
    assert '/tmp/newdata.json' in objects[0].key
