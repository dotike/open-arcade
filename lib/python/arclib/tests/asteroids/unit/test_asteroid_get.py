
import boto3
import os

from moto import mock_s3, mock_sts

from arclib import storage

asd_upload = __import__("asd-upload")
asteroid_upload = __import__("asteroid-upload")
asteroid_get = __import__("asteroid-get")
asd_init = __import__("asd-init")
asteroid_init = __import__("asteroid-init")

@mock_s3
@mock_sts
def test_asteroid_cat(aws_credentials, monkeypatch, valid_asteroid_file, s3_valid_asteroid):
    session = boto3.session.Session()
    storage.get_account_global_bucket(session)

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

    filename = "/tmp/test.json"
    monkeypatch.setattr("sys.argv", ["pytest", "-f", s3_valid_asteroid, "-p", filename])
    asteroid_get.main()

    assert os.path.exists(filename)
    os.remove(filename)
