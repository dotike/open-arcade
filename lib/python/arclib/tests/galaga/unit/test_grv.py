import boto3

from moto import mock_iam, mock_ec2, mock_s3

from arclib import grv 


@mock_iam
def test_create_role(aws_credentials, cluster_policy_arns, cluster_policy_doc):
    res = grv.create_role('test_role_k8', cluster_policy_arns, cluster_policy_doc)
    assert res.endswith('test_role_k8')

    client = boto3.client('iam')
    
    for arn in cluster_policy_arns:
        res = client.attach_role_policy(RoleName='test_role_k8', PolicyArn=arn)

    res = grv.create_role('test_role_k8', cluster_policy_arns, cluster_policy_doc)
    assert res.endswith('test_role_k8')


@mock_iam
def test_find_role(aws_credentials, cluster_policy_arns, cluster_policy_doc):
    res = grv.create_role('test_role_k8', cluster_policy_arns, cluster_policy_doc)
    assert res.endswith('test_role_k8')

    ret = grv.find_role('test_role_k8')
    assert ret['Role']['Arn']
    ret = grv.find_role('invalid')
    assert not ret


@mock_ec2
def test_find_vpc_name(aws_credentials):
    ec2 = boto3.resource('ec2')
    vpc1 = ec2.create_vpc(CidrBlock='10.1.0.0/16')
    vpc2 = ec2.create_vpc(CidrBlock='10.3.0.0/17')

    vpc1.create_tags(Tags=[ {'Key':'Name', 'Value' : 'kind_raw.grv'} ])
    vpc2.create_tags(Tags=[ {'Key':'Name', 'Value' : 'hot_lime.grv'} ])

    assert 'kind_raw.grv' == grv.find_vpc_name(vpc1.id)
    assert 'hot_lime.grv' == grv.find_vpc_name(vpc2.id)


@mock_s3
def test_list_arcade_buckets(aws_credentials):
    gravitar = 'kind_raw.grv'

    name = gravitar.replace('_', '')

    app_bucket = f'test.app.{name}'
    infra_bucket = f'test.infrastructure.{name}'
    assets_bucket = f'test.assets.{name}'

    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket=app_bucket)
    conn.create_bucket(Bucket=infra_bucket)
    conn.create_bucket(Bucket=assets_bucket)

    bucket_dict = grv.list_arcade_buckets(gravitar)

    assert bucket_dict['app'] == app_bucket
    assert bucket_dict['infrastructure'] == infra_bucket
    assert bucket_dict['assets'] == assets_bucket


@mock_s3
def test_get_gravitar_info(aws_credentials):
    gravitar = 'kind_raw.grv'

    name = gravitar.replace('_', '')

    infra_bucket = f'test.infrastructure.{name}'

    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket=infra_bucket)

    assert not grv.get_gravitar_info(gravitar)

    key = 'gravitar/grv_info.json'
    json_content = '{"key1": "val1", "key2": "val2"}'
    conn.Object(infra_bucket, key).put(Body=json_content)

    obj = grv.get_gravitar_info(gravitar)
    assert obj['key1'] == 'val1'
    assert obj['key2'] == 'val2'

@mock_ec2
def test_find_grv_subnets(aws_credentials):
    gravitar = "kind_raw.grv"

    ec2 = boto3.resource('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')

    vpc.create_tags(Tags=[ {'Key':'Name', 'Value' : gravitar} ])

    subnet1 = ec2.create_subnet(CidrBlock='10.0.2.0/24', VpcId=vpc.id)
    subnet2 = ec2.create_subnet(CidrBlock='10.0.4.0/24', VpcId=vpc.id)

    subnet1.create_tags(Tags=[ {'Key':'logical_name', 'Value' : f'core.{gravitar}'} ])
    subnet2.create_tags(Tags=[ {'Key':'logical_name', 'Value' : gravitar} ])

    subnets = grv.find_grv_subnets(gravitar, "core")
    
    assert len(subnets) == 1
    assert subnet1.id in subnets


@mock_ec2
def test_get_vpc_id(aws_credentials):

    ec2 = boto3.resource('ec2')
    vpc1 = ec2.create_vpc(CidrBlock='10.1.0.0/16')
    vpc2 = ec2.create_vpc(CidrBlock='10.3.0.0/17')

    gravitar = 'kind_raw.grv'

    vpc1.create_tags(Tags=[ {'Key':'Name', 'Value' : gravitar} ])
    vpc2.create_tags(Tags=[ {'Key':'Name', 'Value' : 'hot_lime.grv'} ])

    vpc_id = grv.get_vpc_id(gravitar)

    assert vpc_id == vpc1.id

    vpc_id = grv.get_vpc_id('hot_lime.grv')

    assert vpc2.id == vpc_id

    vpc_id = grv.get_vpc_id('not_exist.grv')
    assert not vpc_id 


@mock_ec2
def test_create_grv_sg(aws_credentials):
    gravitar = 'kind_raw.grv'

    ec2 = boto3.resource('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.1.0.0/16')

    vpc.create_tags(Tags=[{'Key': 'Name', 'Value': 'kind_raw.grv'}])

    sg = grv.create_grv_sg(f'test-{gravitar}', vpc.id)

    assert sg


@mock_ec2
def test_delete_grv_sg(aws_credentials):
    gravitar = 'kind_raw.grv'

    ec2 = boto3.resource('ec2')
    client = boto3.client('ec2')

    vpc = ec2.create_vpc(CidrBlock='10.1.0.0/16')

    vpc.create_tags(Tags=[ {'Key':'Name', 'Value' : gravitar} ])

    sg_name = f'test-{gravitar}'

    sg = ec2.create_security_group(Description=sg_name, GroupName=sg_name, VpcId=vpc.id)

    assert isinstance(sg.id, str)

    grv.delete_grv_sg(sg)

    sg_id = grv.check_if_sg(sg_name)

    assert not sg_id


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

    sg_id = grv.check_if_sg(sg_name)

    assert sg_id

    client.delete_security_group(GroupId=sg.id)

    sg_id = grv.check_if_sg(sg_name)

    assert not sg_id


@mock_ec2
def test_find_grv_tag(aws_credentials):
    gravitar = 'kind_raw.grv'

    ec2 = boto3.resource('ec2')
    client = boto3.client('ec2')

    vpc = ec2.create_vpc(CidrBlock='10.1.0.0/16')

    vpc.create_tags(Tags=[ {'Key':'Name', 'Value' : gravitar} ])
    vpc.create_tags(Tags=[ {'Key':'owner', 'Value' : 'test-owner'} ])

    session = boto3.session.Session()

    owner = grv.find_grv_tag(session, gravitar, 'owner')

    assert owner == 'test-owner'
    

@mock_ec2
def test_update_grv_tag(aws_credentials):
    gravitar = 'kind_raw.grv'

    ec2 = boto3.resource('ec2')
    client = boto3.client('ec2')

    vpc = ec2.create_vpc(CidrBlock='10.1.0.0/16')

    vpc.create_tags(Tags=[ {'Key':'Name', 'Value' : gravitar} ])
    vpc.create_tags(Tags=[ {'Key':'owner', 'Value' : 'test-owner'} ])

    session = boto3.session.Session()

    owner = grv.find_grv_tag(session, gravitar, 'owner')

    assert owner == 'test-owner'

    value = grv.update_grv_tag(session, gravitar, 'owner', 'new-value')

    assert 'new-value' == value

    owner = grv.find_grv_tag(session, gravitar, 'owner')

    assert owner == 'new-value'

