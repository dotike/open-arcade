
import boto3
import pytest

from moto import mock_s3, mock_sts

from arclib import storage

asd_upload = __import__("asd-upload")
asd_init = __import__("asd-init")


@mock_s3
@mock_sts
def test_asd_upload(aws_credentials, monkeypatch, valid_asd, invalid_id_asd, invalid_format_asd):
    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

    monkeypatch.setattr("sys.argv", ["pytest"])
    asd_init.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-f", valid_asd])
    asd_upload.main()

    bucket = session.resource('s3').Bucket(bucket_name)

    objects = list(bucket.objects.filter(Prefix='asd/nginxaarf'))
    assert len(objects) == 2
    assert 'asd/nginxaarf/latest' in objects[1].key

    monkeypatch.setattr("sys.argv", ["pytest", "-f", invalid_id_asd])
    with pytest.raises(SystemExit):
        asd_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-f", invalid_format_asd])
    with pytest.raises(SystemExit):
        asd_upload.main()
