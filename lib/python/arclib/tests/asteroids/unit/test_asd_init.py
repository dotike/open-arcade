import boto3
from moto import mock_s3, mock_sts

from arclib import storage

asd_init = __import__('asd-init')


@mock_s3
@mock_sts
def test_asd_init(aws_credentials, monkeypatch):
    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

    monkeypatch.setattr("sys.argv", ["pytest"])
    asd_init.main()

    bucket = session.resource('s3').Bucket(bucket_name)

    objects = list(bucket.objects.filter(Prefix=''))
    assert len(objects) == 1
    assert 'asdschema.json' in objects[0].key
