
import boto3

from moto import mock_s3, mock_sts

from arclib import storage

asteroid_find = __import__("asteroid-find")
asteroid_enable = __import__("asteroid-enable")
asteroid_disable = __import__("asteroid-disable")
asteroid_upload = __import__("asteroid-upload")
asd_init = __import__("asd-init")
asteroid_init = __import__("asteroid-init")
asd_upload = __import__("asd-upload")


@mock_s3
@mock_sts
def test_asteroid_find(monkeypatch, valid_asteroid_file, s3_valid_asteroid):
    arcade = "hot_lime.grv"
    arcade_s3 = arcade.replace('_', '')
    
    session = boto3.session.Session()
    storage.get_account_global_bucket(session)

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
    monkeypatch.setenv('NARC_FOLDER', 'narc')

    monkeypatch.setattr("sys.argv", ["pytest", "-f", s3_valid_asteroid, "--arcade", arcade])
    asteroid_enable.main()

    buckets = storage.get_arcade_buckets(session, arcade)

    target_bucket = resource.Bucket(f'test.app.{arcade_s3}')

    objects = list(target_bucket.objects.filter(Prefix='narc'))
    assert len(objects) == 2

    monkeypatch.setattr("sys.argv", ["pytest", "--asd"])
    asteroid_find.main()

    monkeypatch.setattr("sys.argv", ["pytest", "--asteroid"])
    asteroid_find.main()

    monkeypatch.setattr("sys.argv", ["pytest", "--narc", "--arcade", arcade])
    asteroid_find.main()
