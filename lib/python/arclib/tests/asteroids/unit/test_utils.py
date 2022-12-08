import boto3

from moto import mock_ec2, mock_s3

from arclib import utils, storage


def test_aws_tags_dict():

    narcid = 'narc-test-test-123456'
    assert narcid == utils.get_short_narc_id(narcid)

    narcid = 'narc-testtesttest-testtesttest'
    shortid = 'narc-testtest-testtest'
    assert shortid == utils.get_short_narc_id(narcid)


@mock_ec2
def test_check_if_sg(aws_credentials):
    gravitar = 'kind_raw.grv'

    client = boto3.client('ec2')
    ec2 = boto3.resource('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.1.0.0/16')

    sg_name = f'test-{gravitar}'

    sg = ec2.create_security_group(Description=sg_name, GroupName=sg_name, VpcId=vpc.id)

    # It seems moto didn't create the needed tags when calling grv.create_grv_sg().
    # So adding tags after sg is created.
    sg.create_tags(
        Tags=[
            {
                'Key': 'Name',
                'Value': sg_name
            },
        ]
    )

    sg_id = utils.check_if_sg(sg_name)

    assert sg_id

    client.delete_security_group(GroupId=sg.id)

    sg_id = utils.check_if_sg(sg_name)

    assert not sg_id

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
