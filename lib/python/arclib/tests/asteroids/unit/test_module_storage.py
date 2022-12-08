import boto3
import os

from moto import mock_s3, mock_sts	

from arclib import storage


@mock_s3
def test_upload_to_s3(aws_credentials, test_json_string):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    assert storage.upload_to_s3(session, 'mybucket', test_json_string, 'test/test.json')

    objs = conn.Bucket(name='mybucket').objects.filter(Prefix='test')
    assert len(list(objs)) == 1


@mock_s3
def test_upload_asteroid_json(aws_credentials, test_json_string):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')
 
    storage.upload_asteroid_json(session, 'mybucket', 'asd', 'test', '1', test_json_string) 

    objs = conn.Bucket(name='mybucket').objects.filter(Prefix='asd/test')

    assert len(list(objs)) == 2

    storage.upload_asteroid_json(session, 'mybucket', 'asteroid', 'test', '1', test_json_string) 
    objs = conn.Bucket(name='mybucket').objects.filter(Prefix='asteroid/test')
    assert len(list(objs)) == 2


@mock_s3
def test_get_arcade_buckets(aws_credentials):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')

    arcade = 'kind_raw.grv'

    name = arcade.replace('_', '')

    app_bucket = f'test.app.{name}'
    infra_bucket = f'test.infrastructure.{name}'
    assets_bucket = f'test.assets.{name}'

    conn.create_bucket(Bucket=app_bucket)
    conn.create_bucket(Bucket=infra_bucket)
    conn.create_bucket(Bucket=assets_bucket)

    bucket_dict = storage.get_arcade_buckets(session, arcade)
    assert bucket_dict['app'] == app_bucket
    assert bucket_dict['infrastructure'] == infra_bucket
    assert bucket_dict['assets'] == assets_bucket

    arcade = 'invalid'
    assert not storage.get_arcade_buckets(session, arcade)


@mock_s3
def test_find_s3_keys(aws_credentials, test_json_string):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')
 
    storage.upload_asteroid_json(session, 'mybucket', 'asd', 'test', '1', test_json_string) 
    storage.upload_asteroid_json(session, 'mybucket', 'asteroid', 'test', '1', test_json_string) 

    keys = storage.find_s3_keys(session, 'mybucket', 'asd')
    assert len(keys) == 2

    keys = storage.find_s3_keys(session, 'mybucket', 'asteroid')
    assert len(keys) == 2

    keys = storage.find_s3_keys(session, 'mybucket', 'as')
    assert len(keys) == 4 


@mock_s3
def test_s3_json_to_dict(aws_credentials, test_json_string):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')
 
    storage.upload_asteroid_json(session, 'mybucket', 'asd', 'test', '1', test_json_string) 

    d = storage.s3_json_to_dict(session, 'mybucket', 'asd/test/latest/latest.json')

    assert 'firstName' in d
    assert 'lastName' in d


@mock_s3
@mock_sts
def test_get_account_global_bucket(aws_credentials):

    session = boto3.session.Session()
    bucket = storage.get_account_global_bucket(session)
    
    assert bucket
 
    bucket = storage.get_account_global_bucket(session)
    assert bucket


@mock_s3
def test_delete_s3_prefix(aws_credentials, test_json_string):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')

    storage.upload_to_s3(session, 'mybucket', test_json_string, 'asd/test1.json')
    storage.upload_to_s3(session, 'mybucket', test_json_string, 'asd/test2.json')

    keys = storage.find_s3_keys(session, 'mybucket', 'asd')
    assert len(keys) == 2

    storage.delete_s3_prefix(session, 'mybucket', 'asd/test')
    keys = storage.find_s3_keys(session, 'mybucket', 'asd')
    assert len(keys) == 0

    storage.upload_to_s3(session, 'mybucket', test_json_string, 'asteroid/test1.json')
    storage.upload_to_s3(session, 'mybucket', test_json_string, 'asteroid/test2.json')

    storage.delete_s3_prefix(session, 'mybucket', 'asd/test')
    keys = storage.find_s3_keys(session, 'mybucket', 'asd')
    assert len(keys) == 0

    keys = storage.find_s3_keys(session, 'mybucket', 'asteroid')
    assert len(keys) == 2


@mock_s3
def test_download_s3_file(aws_credentials, test_json_string):
    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket='mybucket')
    
    storage.upload_to_s3(session, 'mybucket', test_json_string, 'asd/test1.json')
    storage.download_s3_file(session, 'mybucket', 'asd/test1.json', '/tmp/test1.json')

    assert os.path.exists('/tmp/test1.json')
    os.remove('/tmp/test1.json')
