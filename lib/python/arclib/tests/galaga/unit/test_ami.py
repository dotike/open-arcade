import boto3
import pytest
from moto import mock_s3, mock_ec2

from arclib import ami


@mock_s3
def test_list_images_in_s3(aws_credentials):
    bucket = 'mybucket'

    session = boto3.session.Session()
    conn = session.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket=bucket)

    key = 'folder/test.vmdk'
    key2 = 'folder/test2.vmdk'
    json_content = '{"key1": "val1", "key2": "val2"}'
    conn.Object(bucket, key).put(Body=json_content)
    conn.Object(bucket, key2).put(Body=json_content)

    ami_list = ami.list_images_in_s3(session, bucket, 'folder/')
    assert ami_list[0]['Name'] == 'test.vmdk'
    assert isinstance(ami_list[1], dict)


@mock_ec2
def test_ami_list_info(aws_credentials):
    session = boto3.session.Session(region_name='us-east-1')
    ec2_client = session.client('ec2')

    image_reservation = ec2_client.run_instances(ImageId="ami-03cf127a", MinCount=1, MaxCount=1)
    instance = image_reservation['Instances'][0]['InstanceId']
    image_response = ec2_client.create_image(InstanceId=instance, Name="test-ami", Description="This is a test ami")
    image_response2 = ec2_client.create_image(InstanceId=instance, Name="test2-ami", Description="This is a test ami")

    ami_list = ami.list_amis(session)
    assert ami_list[0]['Name'] == 'test-ami'
    assert isinstance(ami_list[1], dict)

    ami_dict = ami.ami_info(session, ami_list[0]['ImageId'])
    assert ami_dict['ImageId'] == ami_list[0]['ImageId']

    assert ami.copy_ami(session, ami_dict['ImageId'], ['us-east-1', 'us-east-2', 'us-west-1'])
    assert ami.copy_ami(session, ami_dict['ImageId'], ['us-east-2', 'us-west-1'])
