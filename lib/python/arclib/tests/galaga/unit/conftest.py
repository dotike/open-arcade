import os
import pytest

ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}


ASSUME_NODEGROUP_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}


@pytest.fixture
def cluster_policy_arns():
    return ['arn:aws:iam::aws:policy/AmazonEKSClusterPolicy']


@pytest.fixture
def cluster_policy_doc():
    return ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT 


@pytest.fixture
def aws_credentials():
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing' 
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing' 


@pytest.fixture
def gsd_schema():
    return 'gsdschema.json'


@pytest.fixture
def gsd_alb():
    return 'misc/demo/alb.json'


@pytest.fixture
def gsd_eks():
    return 'misc/demo/eks.json'


@pytest.fixture
def gsd_nodegroup():
    return 'misc/demo/nodegroup.json'


@pytest.fixture
def kind_raw_json():
    return 'misc/galaga-examples/kind_raw.json'


@pytest.fixture
def s3_kind_raw_json():
    return 'galaga/kind_raw/latest/latest.json'


@pytest.fixture
def s3_gsd_eks():
    return 'galaga/galaga/gsd/eks/latest/latest.json'


@pytest.fixture
def s3_gsd_nodegroup():
    return 'galaga/galaga/gsd/nodegroup/latest/latest.json'


@pytest.fixture
def s3_gsd_alb():
    return 'galaga/galaga/gsd/alb/latest/latest.json'
