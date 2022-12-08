
import boto3
import json

from moto import mock_s3, mock_sts

from arclib import storage

asteroid_upload = __import__("asteroid-upload")
asd_upload = __import__("asd-upload")
asteroid_dump = __import__("asteroid-dump")
asd_init = __import__("asd-init")
asteroid_init = __import__("asteroid-init")


@mock_s3
@mock_sts
def test_asteroid_dump(capsys, monkeypatch, valid_asteroid_file, s3_valid_asteroid):
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

    monkeypatch.setattr("sys.argv", ["pytest", "-a", 'testasteroid'])

    capsys.readouterr()
    asteroid_dump.main()
    captured = capsys.readouterr()

    data = json.loads(captured.out)

    assert len(data) == 2
