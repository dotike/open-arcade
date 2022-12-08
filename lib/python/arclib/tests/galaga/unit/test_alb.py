import boto3

from moto import mock_ec2, mock_elbv2, mock_route53

from arclib import alb


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

    arn = alb.find_alb_arn(alb_name)

    assert f'loadbalancer/{alb_name}' in arn


@mock_elbv2
@mock_ec2
@mock_route53
def test_alb_create(aws_credentials):
    ec2 = boto3.resource("ec2")

    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')

    gravitar = 'kind_raw.grv'

    r53 = boto3.client('route53')
    r53.create_hosted_zone(
            Name=gravitar,
            CallerReference=str(hash("test")),
            VPC={
                'VPCRegion': 'us-east-2',
                'VPCId': vpc.id
            }
        )

    vpc.create_tags(Tags=[{'Key': 'Name', 'Value': gravitar}])

    subnet1 = ec2.create_subnet(CidrBlock='10.0.2.0/24', VpcId=vpc.id)
    subnet2 = ec2.create_subnet(CidrBlock='10.0.4.0/24', VpcId=vpc.id)
    subnet3 = ec2.create_subnet(CidrBlock='10.0.6.0/24', VpcId=vpc.id)

    subnet1.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'core.{gravitar}'}])
    subnet2.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'wan.{gravitar}'}])
    subnet3.create_tags(Tags=[{'Key': 'logical_name', 'Value': gravitar}])

    res = alb.alb_create(gravitar, True)

    assert 'active' == res['State']['Code']

    res = alb.alb_create(gravitar, False)

    assert 'active' == res['State']['Code']


@mock_elbv2
@mock_ec2
@mock_route53
def test_alb_delete(aws_credentials):
    ec2 = boto3.resource("ec2")

    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')

    gravitar = 'kind_raw.grv'

    r53 = boto3.client('route53')
    r53.create_hosted_zone(
            Name=gravitar,
            CallerReference=str(hash("test")),
            VPC={
                'VPCRegion': 'us-east-2',
                'VPCId': vpc.id
            }
        )

    vpc.create_tags(Tags=[ {'Key':'Name', 'Value' : gravitar} ])

    subnet1 = ec2.create_subnet(CidrBlock='10.0.2.0/24', VpcId=vpc.id)
    subnet2 = ec2.create_subnet(CidrBlock='10.0.4.0/24', VpcId=vpc.id)
    subnet3 = ec2.create_subnet(CidrBlock='10.0.6.0/24', VpcId=vpc.id)

    subnet1.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'core.{gravitar}'}])
    subnet2.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'wan.{gravitar}'}])
    subnet3.create_tags(Tags=[{'Key': 'logical_name', 'Value': gravitar}])

 
    alb.alb_create(gravitar, True)

    alb.alb_create(gravitar, False)

    res = alb.delete_alb(gravitar, True)

    assert res

    res = alb.delete_alb(gravitar, False)

    assert res


@mock_elbv2
@mock_ec2
@mock_route53
def test_alb_connect_sg(aws_credentials):
    ec2 = boto3.resource("ec2")

    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')

    gravitar = 'kind_raw.grv'

    r53 = boto3.client('route53')
    r53.create_hosted_zone(
            Name=gravitar,
            CallerReference=str(hash("test")),
            VPC={
                'VPCRegion': 'us-east-2',
                'VPCId': vpc.id
            }
        )

    vpc.create_tags(Tags=[{'Key': 'Name', 'Value': gravitar}])

    subnet1 = ec2.create_subnet(CidrBlock='10.0.2.0/24', VpcId=vpc.id)
    subnet2 = ec2.create_subnet(CidrBlock='10.0.4.0/24', VpcId=vpc.id)
    subnet3 = ec2.create_subnet(CidrBlock='10.0.6.0/24', VpcId=vpc.id)

    subnet1.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'core.{gravitar}'}])
    subnet2.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'wan.{gravitar}'}])
    subnet3.create_tags(Tags=[{'Key': 'logical_name', 'Value': gravitar}])

    sg_nat_name = f"nat.{gravitar}"
    sg_nat = ec2.create_security_group(
        GroupName=sg_nat_name, Description=sg_nat_name, VpcId=vpc.id
    )

    sg_nat.create_tags(
        Tags=[
            {
                'Key': 'Name',
                'Value': sg_nat_name
            },
        ]
    )

    alb.alb_create(gravitar, True)

    alb.alb_create(gravitar, False)

    cluster = 'asteroids-kind_raw-grv'

    sg_name = f"eks-cluster-sg-{cluster}"

    sg = ec2.create_security_group(
        GroupName=sg_name, Description=sg_name, VpcId=vpc.id
    )

    sg.create_tags(
        Tags=[
            {
                'Key': 'Name',
                'Value': sg_name
            },
        ]
    )

    res = alb.alb_connect_sg(gravitar, cluster, True)

    assert res

    res = alb.alb_connect_sg(gravitar, cluster, False)

    assert res


@mock_elbv2
@mock_ec2
@mock_route53
def test_alb_info(aws_credentials):
    ec2 = boto3.resource("ec2")

    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')

    gravitar = 'kind_raw.grv'

    r53 = boto3.client('route53')
    r53.create_hosted_zone(
            Name=gravitar,
            CallerReference=str(hash("test")),
            VPC={
                'VPCRegion': 'us-east-2',
                'VPCId': vpc.id
            }
        )

    vpc.create_tags(Tags=[{'Key': 'Name', 'Value': gravitar}])

    subnet1 = ec2.create_subnet(CidrBlock='10.0.2.0/24', VpcId=vpc.id)
    subnet2 = ec2.create_subnet(CidrBlock='10.0.4.0/24', VpcId=vpc.id)
    subnet3 = ec2.create_subnet(CidrBlock='10.0.6.0/24', VpcId=vpc.id)

    subnet1.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'core.{gravitar}'}])
    subnet2.create_tags(Tags=[{'Key': 'logical_name', 'Value': f'wan.{gravitar}'}])
    subnet3.create_tags(Tags=[{'Key': 'logical_name', 'Value': gravitar}])

    sg_nat_name = f"nat.{gravitar}"
    sg_nat = ec2.create_security_group(
        GroupName=sg_nat_name, Description=sg_nat_name, VpcId=vpc.id
    )

    sg_nat.create_tags(
        Tags=[
            {
                'Key': 'Name',
                'Value': sg_nat_name
            },
        ]
    )

    alb.alb_create(gravitar, True)

    alb.alb_create(gravitar, False)

    cluster = 'asteroids-kind_raw-grv'

    sg_name = f"eks-cluster-sg-{cluster}"

    sg = ec2.create_security_group(
        GroupName=sg_name, Description=sg_name, VpcId=vpc.id
    )

    sg.create_tags(
        Tags=[
            {
                'Key': 'Name',
                'Value': sg_name
            },
        ]
    )

    public_alb_name = f"public-{gravitar.replace('_', '').replace('.', '-')}"
    private_alb_name = f"private-{gravitar.replace('_', '').replace('.', '-')}"

    alb.alb_connect_sg(gravitar, cluster, True)

    alb.alb_connect_sg(gravitar, cluster, False)

    info = alb.alb_info(gravitar)

    assert public_alb_name in info['loadbalancers']
    assert private_alb_name in info['loadbalancers']


@mock_elbv2
@mock_ec2
def test_get_alb_status(aws_credentials):
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

    res = alb.get_alb_status(alb_name)
    assert 'active' == res['State']['Code']

    res = alb.get_alb_status("Invalid_alb")

    assert 'Error' in res


@mock_elbv2
@mock_ec2
def test_find_sg_attached(aws_credentials):
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

    res = alb.find_sg_attached(alb_name)
    assert res == sg.id


def test_get_alb_dict():
    gravitar = 'kind_raw.grv'
    public_dict = alb.get_alb_dict(gravitar, True)
    private_dict = alb.get_alb_dict(gravitar, False)

    assert 'internet-facing' in public_dict['scheme']
    assert 'internal' in private_dict['scheme']

    assert public_dict['name'].startswith('public')
    assert private_dict['sg_name'].startswith('private')
