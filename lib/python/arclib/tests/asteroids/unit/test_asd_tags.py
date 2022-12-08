import boto3
import json
from moto import mock_s3, mock_sts

from arclib import storage

asd_tags = __import__('asd-tags')


@mock_s3
@mock_sts
def test_asd_tags(aws_credentials, monkeypatch):
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

    monkeypatch.setattr("sys.argv", ["pytest", "-f", key])
    asd_tags.main()

    bucket = session.resource('s3').Bucket(bucket_name)

    objects = list(bucket.objects.filter(Prefix=''))
    assert len(objects) == 1
    assert '/tmp/data.json' in objects[0].key
