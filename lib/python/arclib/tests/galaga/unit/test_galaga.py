
import boto3
import json
import pytest

from moto import mock_s3

from galaga import Galaga 
galaga_upload = __import__("galaga-upload")
galaga_add = __import__("galaga-add")
galaga_create = __import__("galaga-create")
gsd_init = __import__("gsd-init")
gsd_upload = __import__("gsd-upload")


@pytest.fixture
def kind_raw_galaga(kind_raw_json):
    g = Galaga()
    g.from_file(kind_raw_json)
    return g


def test_new_galaga():
    g = Galaga("name", 10)
    assert g.name == 'name'
    assert g.version == 10


def test_from_file(kind_raw_json):
    g = Galaga()
    g.from_file(kind_raw_json)
    assert g.name == 'kind_raw'
    with pytest.raises(Exception):
        g.from_file('invalid_file.json')


def test_validate(kind_raw_json, gsd_eks):
    with open(kind_raw_json) as f:
        assert Galaga.validate(json.load(f))

    with open(gsd_eks) as f:
        assert not Galaga.validate(json.load(f))


@mock_s3
def test_from_s3(aws_credentials, monkeypatch, kind_raw_json, s3_kind_raw_json, gsd_eks, s3_gsd_eks):
    g = Galaga()
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    with pytest.raises(Exception):
        g.from_s3_object('mybucket', 'missing.json')

    monkeypatch.setenv('GALAGA_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest", "-f", kind_raw_json])
    galaga_upload.main()

    monkeypatch.setenv('GSD_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest"])
    gsd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_eks])
    gsd_upload.main()

    g.from_s3_object('mybucket', s3_kind_raw_json)
    assert g.name == 'kind_raw'

    with pytest.raises(Exception):
        g.from_s3_object('mybucket', s3_gsd_eks)


def test_add_component(kind_raw_galaga):
    kind_raw_galaga.add_component('test_service', 'test_location')
    assert 'test_service' in kind_raw_galaga.components
    assert kind_raw_galaga.components['test_service']['location'] == 'test_location'


def test_to_json(kind_raw_galaga):
    string = kind_raw_galaga.to_json()
    obj = json.loads(string)
    assert kind_raw_galaga.name == obj['name']


def test_add_override(kind_raw_galaga, gsd_eks):
    with open(gsd_eks) as f:
        gsd_json = json.load(f)

    kind_raw_galaga.add_override(gsd_json, "service_options/eks_version=100")

    assert 'service_options/eks_version' in kind_raw_galaga.components[gsd_json['component_type']]['overrides']
    assert kind_raw_galaga.components[gsd_json['component_type']]['overrides']['service_options/eks_version'] == "100"


@mock_s3
def test_check_dependency(aws_credentials, monkeypatch, gsd_eks, gsd_nodegroup, gsd_alb, s3_gsd_eks, s3_gsd_nodegroup, s3_gsd_alb):
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    monkeypatch.setenv('GSD_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest"])
    gsd_init.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_eks])
    gsd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_nodegroup])
    gsd_upload.main()
    monkeypatch.setattr("sys.argv", ["pytest", "-f", gsd_alb])
    gsd_upload.main()

    monkeypatch.setenv('GALAGA_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest", "-a", "kind_raw"])
    galaga_create.main()

    monkeypatch.setattr("sys.argv", ["pytest", "-a", "kind_raw", "-f", s3_gsd_nodegroup])
    galaga_add.main()

    g = Galaga()
    g.from_file('/tmp/kind_raw.json')
    missing = g.check_dependency('mybucket')
    assert len(missing) == 2 

    monkeypatch.setenv('GALAGA_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest", "-a", "kind_raw", "-f", s3_gsd_alb])
    galaga_add.main()

    g = Galaga()
    g.from_file('/tmp/kind_raw.json')
    missing = g.check_dependency('mybucket')
    assert len(missing) == 1

    monkeypatch.setenv('GALAGA_BUCKET', 'mybucket')
    monkeypatch.setattr("sys.argv", ["pytest", "-a", "kind_raw", "-f", s3_gsd_eks])
    galaga_add.main()

    g = Galaga()
    g.from_file('/tmp/kind_raw.json')
    missing = g.check_dependency('mybucket')
    assert not len(missing)