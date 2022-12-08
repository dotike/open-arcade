import boto3
import pytest

from arclib import k8s

from arclib import storage

asteroid_enable = __import__("asteroid-enable")
asteroid_disable = __import__("asteroid-disable")
narc_reconcile = __import__("narc-reconcile")


@pytest.fixture
def arcade():
    return "puny_jam.grv"


@pytest.fixture
def asteroid():
    return "woofaarf"


@pytest.fixture
def target_bucket():
    return "ee97bcb.app.punyjam.grv"


def test_demo(monkeypatch, target_bucket, asteroid, arcade):
    session = boto3.session.Session()
    storage.get_account_global_bucket(session)

    monkeypatch.setenv('NARC_FOLDER', 'narc')
    monkeypatch.setattr("sys.argv", ["pytest", "-a", asteroid, "--arcade", arcade])

    asteroid_enable.main()

    bucket = session.resource('s3').Bucket(target_bucket)

    objects = list(bucket.objects.filter(Prefix='narc/woofaarf'))
    assert len(objects) == 2

    monkeypatch.setattr("sys.argv", ["pytest", "-g", arcade])
    narc_reconcile.main()

    deployments = k8s.get_asteroid_running_services(asteroid)
    print(deployments)
    assert len(deployments) == 2

    monkeypatch.setattr("sys.argv", ["pytest", "-a", asteroid, "--arcade", arcade])
    asteroid_disable.main()

    objects = list(bucket.objects.filter(Prefix='narc/woofaarf'))
    assert len(objects) == 0

    monkeypatch.setattr("sys.argv", ["pytest", "-g", arcade])
    narc_reconcile.main()

    deployments = k8s.get_asteroid_running_services(asteroid)
    assert len(deployments) == 0
