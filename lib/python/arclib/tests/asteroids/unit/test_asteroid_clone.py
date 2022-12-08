
import boto3
import os

from moto import mock_s3, mock_sts

from arclib import storage

asteroid_create = __import__("asteroid-create")
asteroid_add = __import__("asteroid-add")
asteroid_clone = __import__("asteroid-clone")
asd_init = __import__("asd-init")
asteroid_init = __import__("asteroid-init")
asd_upload = __import__("asd-upload")
asteroid_upload = __import__("asteroid-upload")


@mock_s3
@mock_sts
def test_asteroid_clone(aws_credentials, monkeypatch):
    asteroid_file = "/tmp/woofaarf.json"
    if os.path.exists(asteroid_file):
        os.remove(asteroid_file)
    monkeypatch.setenv('TMP_DIR', '/tmp')
    asteroid = "woofaarf"
    monkeypatch.setattr("sys.argv", ["pytest", "-a", asteroid])
    asteroid_create.main()
    assert os.path.exists(asteroid_file)

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)

    monkeypatch.setattr("sys.argv", ["pytest"])
    asd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest"])
    asteroid_init.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxaarf.json'])
    asd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxwoof.json'])
    asd_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-a", asteroid, "-f", 'asd/nginxaarf/latest/latest.json'])
    asteroid_add.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-a", asteroid, "-f", 'asd/nginxwoof/latest/latest.json'])
    asteroid_add.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-f", "/tmp/woofaarf.json"])
    asteroid_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-a", asteroid, '-t', "default", "-r", "us-west-2"])
    asteroid_clone.main()

    keys = storage.find_s3_keys(session, bucket, "asd/")
    assert len(keys) == 4

    keys = storage.find_s3_keys(session, bucket, "asteroid/")
    assert len(keys) == 2
