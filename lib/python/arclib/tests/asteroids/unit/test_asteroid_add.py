
import boto3
import json
import pytest
import os

from moto import mock_s3, mock_sts

from arclib import storage

asteroid_create = __import__("asteroid-create")
asteroid_add = __import__("asteroid-add")
asd_init = __import__("asd-init")
asteroid_init = __import__("asteroid-init")
asd_upload = __import__("asd-upload")


@pytest.fixture
def asd_keys():
    return ['asd/nginxaarf/latest/latest.json',
            'asd/nginxwoof/latest/latest.json']


@mock_s3
@mock_sts
def test_asteroid_add(aws_credentials, monkeypatch, dummy_asteroid_file, asd_keys):
    if os.path.exists(dummy_asteroid_file):
        os.remove(dummy_asteroid_file)
    monkeypatch.setenv('TMP_DIR', '/tmp')
    monkeypatch.setattr("sys.argv", ["pytest", "-a", "dummyasteroid"])
    asteroid_create.main()
    assert os.path.exists(dummy_asteroid_file)

    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'invalid'])

    with pytest.raises(SystemExit):
        asteroid_add.main()

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

    for i in range(len(asd_keys)):
        monkeypatch.setattr("sys.argv", ["pytest", "-a", "dummyasteroid", "-f", asd_keys[i]])
        asteroid_add.main()
        monkeypatch.setattr("sys.argv", ["pytest", "-a", "dummyasteroid", "-f", asd_keys[i], '-o', 'version=3'])
        asteroid_add.main()
        monkeypatch.setattr("sys.argv", ["pytest", "-a", "dummyasteroid", "-f", asd_keys[i], '-o',
                                         'service_options/load_balanced/private=true'])
        asteroid_add.main()

        groups = asd_keys[i].split('/')

        with open(dummy_asteroid_file) as f:
            data = json.load(f)
            assert len(data['services']) == i+1
            assert data['services'][groups[1]]['overrides']['version'] == 3
            assert data['services'][groups[1]]['overrides']['service_options/load_balanced/private'] == 'true'

    os.remove(dummy_asteroid_file)
