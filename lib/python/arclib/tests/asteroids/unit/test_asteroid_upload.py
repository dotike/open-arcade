
import boto3

from moto import mock_s3, mock_sts

from arclib import storage

asd_upload = __import__("asd-upload")
asteroid_upload = __import__("asteroid-upload")
asd_init = __import__("asd-init")
asteroid_init = __import__("asteroid-init")


@mock_s3
@mock_sts
def test_asteroid_upload(aws_credentials, monkeypatch, valid_asteroid_file):
    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

    monkeypatch.setattr("sys.argv", ["pytest"])
    asd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest"])
    asteroid_init.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxaarf.json'])
    asd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxwoof.json'])
    asd_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-f", valid_asteroid_file])
    asteroid_upload.main()

    bucket = session.resource('s3').Bucket(bucket_name)

    objects = list(bucket.objects.filter(Prefix='asteroid/testasteroid'))
    assert len(objects) == 2
    assert 'asteroid/testasteroid/latest' in objects[1].key

