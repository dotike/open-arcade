import boto3
import pytest

from moto import mock_ec2, mock_s3, mock_route53

from arclib import utils


def test_aws_tags_dict():

    with pytest.raises(ValueError):
        utils.aws_tags_dict(None)

    assert not utils.aws_tags_dict([])

    with pytest.raises(ValueError):
        utils.aws_tags_dict("test")

    assert utils.aws_tags_dict([{'Key': 'test', 'Value': 'val'}])['test'] == 'val'

    ret = utils.aws_tags_dict([{'Key': 'test1', 'Value': 'val1'}, {'Key': 'test2', 'Value': 'val2'}])
    assert ret['test1'] == 'val1'
    assert ret['test2'] == 'val2'


def test_check_dryrun(monkeypatch):
    monkeypatch.setenv('GALAGA_DRYRUN', '1')
    assert utils.check_dryrun('test')

    monkeypatch.setenv('GALAGA_DRYRUN', '0')
    assert not utils.check_dryrun('test')


def test_print_status():
    from datetime import datetime
    now = datetime.now()
    status = {'test': 'test', 'created': now}
    utils.print_status(status)


@mock_s3
def test_setup_arcade_session(aws_credentials):
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

    arcade_session = utils.setup_arcade_session(arcade)

    assert type(arcade_session) == type(session)


@mock_route53
@mock_ec2
def test_add_arcade_cname(aws_credentials):
    session = boto3.session.Session()
    r53 = session.client('route53')

    arcade = 'kind_raw.grv'

    ec2 = session.resource('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')

    response = r53.create_hosted_zone(
            Name=arcade, 
            CallerReference=str(hash("test")),
            VPC={
                'VPCRegion': 'us-east-2',
                'VPCId': vpc.id
            }
        )

    utils.add_arcade_cname(arcade, "test.kind_raw.grv", "dummy.com")

    res = r53.list_resource_record_sets(HostedZoneId=response["HostedZone"]['Id'], StartRecordName="test.kind_raw.grv", MaxItems='1') 

    assert 'test.kind_raw.grv' in res['ResourceRecordSets'][0]['Name']
    assert res['ResourceRecordSets'][0]['ResourceRecords'][0]['Value'] == 'dummy.com' 


@mock_route53
@mock_ec2
def test_delete_arcade_cname(aws_credentials):
    session = boto3.session.Session()
    r53 = session.client('route53')

    arcade = 'kind_raw.grv'

    ec2 = session.resource('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')

    response = r53.create_hosted_zone(
            Name=arcade,
            CallerReference=str(hash("test")),
            VPC={
                'VPCRegion': 'us-east-2',
                'VPCId': vpc.id
            }
        )

    utils.add_arcade_cname(arcade, "test.kind_raw.grv", "dummy.com")

    res = r53.list_resource_record_sets(HostedZoneId=response["HostedZone"]['Id'], StartRecordName="test.kind_raw.grv", MaxItems='1')
    
    assert len(res['ResourceRecordSets']) == 1

    utils.delete_arcade_cname(arcade, "test.kind_raw.grv")

    res = r53.list_resource_record_sets(HostedZoneId=response["HostedZone"]['Id'], StartRecordName="test.kind_raw.grv", MaxItems='1')

    assert len(res['ResourceRecordSets']) == 0 

