import boto3

from moto import mock_s3, mock_sts

from arclib import storage

narc_upload = __import__("narc-upload")
narc_dump = __import__("narc-dump")
narc_list = __import__("narc-list")
asteroid_init = __import__("asteroid-init")
asteroid_enable = __import__("asteroid-enable")
asteroid_disable = __import__("asteroid-disable")
asteroid_upload = __import__("asteroid-upload")
asd_init = __import__("asd-init")
asd_upload = __import__("asd-upload")

@mock_s3
@mock_sts
def test_narc_upload(capsys, monkeypatch, valid_asteroid_file, s3_valid_asteroid):
    session = boto3.session.Session()
    storage.get_account_global_bucket(session)

    arcade = 'wet_sea.grv'
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

    monkeypatch.setenv('NARC_FOLDER', 'narc')

    monkeypatch.setattr("sys.argv", ["pytest", "-f", s3_valid_asteroid, "--arcade", arcade])
    asteroid_enable.main()
    target_bucket = resource.Bucket(f'test.app.{arcade_s3}')
    
    monkeypatch.setattr("sys.argv", ["pytest", "--arcade", arcade, "--bucket", target_bucket.name])
    capsys.readouterr()
    narc_list.main()
    captured = capsys.readouterr()
    
    narc_nginxaarf = captured.out.split()[1]
    narc_nginxwoof = captured.out.split()[3]
    
    monkeypatch.setattr("sys.argv", ["pytest", "--arcade", arcade, "--bucket", target_bucket.name, "--file", narc_nginxaarf.split('/')[1], "--save"])
    capsys.readouterr()
    narc_dump.main()
    captured = capsys.readouterr()
    downloaded_file_1 = captured.out.split()[0]

    monkeypatch.setattr("sys.argv", ["pytest", "--arcade", arcade, "--bucket", target_bucket.name, "--file", narc_nginxwoof.split('/')[1], "--save"])
    capsys.readouterr()
    narc_dump.main()
    captured = capsys.readouterr()
    downloaded_file_2 = captured.out.split()[0]

    monkeypatch.setattr("sys.argv", ["pytest", "--arcade", arcade, "--bucket", target_bucket.name, "--file", downloaded_file_1])
    narc_upload.main()

    monkeypatch.setattr("sys.argv", ["pytest", "--arcade", arcade, "--bucket", target_bucket.name, "--file", downloaded_file_2])
    narc_upload.main()

    objects = list(target_bucket.objects.filter(Prefix='narc'))
    assert len(objects) == 4
    
    monkeypatch.setattr("sys.argv", ["pytest", "-f", s3_valid_asteroid, "--arcade", arcade])
    asteroid_disable.main()
    
    objects = list(target_bucket.objects.filter(Prefix='narc'))
    assert len(objects) == 2

    storage.delete_s3_prefix(session, target_bucket.name, 'narc')

    objects = list(target_bucket.objects.filter(Prefix='narc'))

    assert len(objects) == 0

