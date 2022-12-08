import boto3

from moto import mock_ec2, mock_elbv2

from narc_ingress import find_alb_arn


@mock_elbv2
@mock_ec2
def test_find_alb_arn(aws_credentials):
    conn = boto3.client("elbv2")
    ec2 = boto3.resource("ec2")

    sg = ec2.create_security_group(
        GroupName="test-security-group", Description="Test"
    )
    vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24")
    subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="172.28.7.0/26")

    alb_name = 'test-alb'
    grv_name = "kind_raw.grv"

    conn.create_load_balancer(
        Name=alb_name,
        Subnets=[subnet.id],
        SecurityGroups=[sg.id],
        Scheme="internal",
        Tags=[{"Key": "Name", "Value": alb_name}, {"Key": "grv_name", "Value": grv_name}],
    )

    arn = find_alb_arn(alb_name)

    assert f'loadbalancer/{alb_name}' in arn
