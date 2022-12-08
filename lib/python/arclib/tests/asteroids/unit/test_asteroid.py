
import boto3
import json
import pytest

from moto import mock_s3, mock_sts

from asteroid import Asteroid
from arclib import storage

asteroid_upload = __import__("asteroid-upload")
asd_init = __import__("asd-init")
asteroid_init = __import__("asteroid-init")
asd_upload = __import__("asd-upload")

with open(Asteroid.ASTEROID_SCHEMA_FILE) as fp:
    Asteroid.ASTEROID_SCHEMA = json.loads(fp.read())

with open(Asteroid.ASD_SCHEMA_FILE) as fp:
    Asteroid.ASD_SCHEMA = json.loads(fp.read())


@pytest.fixture
def asteroid(valid_asteroid_file):
    a = Asteroid()
    a.from_file(valid_asteroid_file)
    return a


def test_new_asteroid():
    a = Asteroid("name", 10)
    assert a.name == 'name'
    assert a.version == 10


def test_from_data(valid_asteroid_file):
    a = Asteroid()
    with open(valid_asteroid_file) as fp:
        data = json.loads(fp.read())
    a.from_data(data)
    assert a.name == 'testasteroid'


def test_from_file(valid_asteroid_file, invalid_asteroid_file, invalid_asteroid_id_file):
    a = Asteroid()
    a.from_file(valid_asteroid_file)
    assert a.name == 'testasteroid'
    with pytest.raises(Exception):
        a.from_file(invalid_asteroid_file)
    with pytest.raises(Exception):
        a.from_file(invalid_asteroid_id_file)


def test_validate(valid_asteroid_file, invalid_asteroid_file):
    with open(valid_asteroid_file) as f:
        assert Asteroid.validate(json.load(f))

    with open(invalid_asteroid_file) as f:
        assert not Asteroid.validate(json.load(f))


def test_id_validate():
    assert not Asteroid.id_validate("")
    assert not Asteroid.id_validate("test_asteroid")
    assert not Asteroid.id_validate("test-asteroid")
    assert not Asteroid.id_validate("test.asteroid")
    assert not Asteroid.id_validate("123testasteroid")
    assert Asteroid.id_validate("testasteroid")
    assert Asteroid.id_validate("testasteroid123")
    assert not Asteroid.id_validate("a23")
    assert Asteroid.id_validate("a234")
    assert Asteroid.id_validate("a234567890123456") 
    assert not Asteroid.id_validate("a2345678901234567") 


def test_add_metadata(asteroid):
    asteroid.add_metadata('test_metadata', 'test_value')
    assert asteroid.metadata['test_metadata'] == 'test_value'


def test_add_tag(asteroid):
    asteroid.add_tag('test_tag', 'test_value')
    assert asteroid.tags['test_tag'] == 'test_value'


def test_add_service(asteroid):
    asteroid.add_service('test_service', 'test_location')
    assert 'test_service' in asteroid.services
    assert asteroid.services['test_service']['location'] == 'test_location'


def test_to_json(asteroid):
    string = asteroid.to_json()
    obj = json.loads(string)
    assert asteroid.name == obj['name']


@mock_s3
@mock_sts
def test_from_s3(aws_credentials, monkeypatch, valid_asteroid_file, s3_valid_asteroid, s3_valid_asd, s3_missing_obj):
    a = Asteroid()

    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

    with pytest.raises(Exception):
        a.from_s3_object(bucket_name, s3_missing_obj)

    monkeypatch.setattr("sys.argv", ["pytest"])
    asd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest"])
    asteroid_init.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxwoof.json'])
    asd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxaarf.json'])
    asd_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-f", valid_asteroid_file])
    asteroid_upload.main()

    a.from_s3_object(bucket_name, s3_valid_asteroid)
    assert a.name == 'testasteroid'

    with pytest.raises(Exception):
        a.from_s3_object(bucket_name, s3_valid_asd)


@mock_s3
@mock_sts
def test_add_override(aws_credentials, monkeypatch, valid_asteroid_file, s3_valid_asd):
    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

    monkeypatch.setattr("sys.argv", ["pytest"])
    asd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest"])
    asteroid_init.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxwoof.json'])
    asd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxaarf.json'])
    asd_upload.main()

    asd = storage.s3_json_to_dict(session, bucket_name, s3_valid_asd)

    monkeypatch.setattr("sys.argv", ["pytest", "-f", valid_asteroid_file])
    asteroid_upload.main()

    asteroid = Asteroid()
    asteroid.from_file(valid_asteroid_file)
    asteroid.add_override(asd, f"version=100")

    assert 'version' in asteroid.services[asd['service']]['overrides']
    assert asteroid.services[asd['service']]['overrides']['version'] == 100

    asteroid.add_override(asd, f"service_options/deployment_strategy/type=rolling")
    assert 'service_options/deployment_strategy/type' in asteroid.services[asd['service']]['overrides']
    assert asteroid.services[asd['service']]['overrides']['service_options/deployment_strategy/type'] == 'rolling'

    asteroid.add_override(asd, f"service_options/load_balanced/public=true")
    assert 'service_options/load_balanced/public' in asteroid.services[asd['service']]['overrides']
    assert asteroid.services[asd['service']]['overrides']['service_options/load_balanced/public'] == 'true'


@mock_s3
@mock_sts
def test_to_narc(aws_credentials, monkeypatch, valid_asteroid_file, s3_valid_asteroid):
    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

    a = Asteroid()

    arcade = 'hot_lime.grv'
    arcade_s3 = arcade.replace('_', '')

    resource = session.resource('s3')

    resource.create_bucket(Bucket=f'test.app.{arcade_s3}',
                           CreateBucketConfiguration=
                           {'LocationConstraint': session.region_name})

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

    a.from_s3_object(bucket_name, s3_valid_asteroid)
    a.to_narc(bucket_name, f'test.app.{arcade_s3}', 'narc')

    bucket = session.resource('s3').Bucket(f'test.app.{arcade_s3}')

    objects = list(bucket.objects.filter(Prefix='narc'))
    assert len(objects) == 2


@mock_s3
@mock_sts
def test_generate_narc(aws_credentials, monkeypatch, valid_asteroid_file, asteroid, s3_valid_asteroid, s3_valid_asd):
    session = boto3.session.Session()
    bucket_name = storage.get_account_global_bucket(session)

    arcade = 'hot_lime.grv'
    arcade_s3 = arcade.replace('_', '')

    resource = session.resource('s3')

    resource.create_bucket(Bucket=f'test.app.{arcade_s3}',
                           CreateBucketConfiguration=
                           {'LocationConstraint': session.region_name})

    monkeypatch.setattr("sys.argv", ["pytest"])
    asd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxaarf.json'])
    asd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", 'misc/demo/nginxwoof.json'])
    asd_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-f", valid_asteroid_file])
    asteroid_upload.main()

    asd = storage.s3_json_to_dict(session, bucket_name, s3_valid_asd)

    asteroid.add_override(asd, f"service_options/deployment_strategy/type=rolling")
    asteroid.add_override(asd, f"service_options/load_balanced/public=true")

    asteroid.generate_narc(bucket_name)

    key = ""
    for k in asteroid.narc_dict.keys():
        if 'nginxaarf' in k:
            key = k

    assert 'deployment_strategy' in asteroid.narc_dict[key]['service_options']
    assert 'type' in asteroid.narc_dict[key]['service_options']['deployment_strategy']
    assert 'rolling' == asteroid.narc_dict[key]['service_options']['deployment_strategy']['type']
    assert True == asteroid.narc_dict[key]['service_options']['load_balanced']['public']
