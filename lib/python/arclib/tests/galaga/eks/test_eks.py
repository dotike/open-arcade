import pytest

from arclib import eks


@pytest.fixture
def vpc_name():
    # vpc id of damp_red.grv
    return 'vpc-0265bb871f9960c37'


@pytest.fixture
def cluster_name():
    return 'asteroids-kind_raw-grv'


@pytest.fixture
def nodegroup():
    return 'asteroids_nodegroup-kind_raw-grv'


@pytest.fixture
def read_gravitar():
    return 'kind_raw.grv'


@pytest.fixture
def write_gravitar():
    return 'damp_red.grv'


def test_info_eks(cluster_name):
    info = eks.info_eks(cluster_name)
    assert info['name'] == cluster_name


def test_list_eks(read_gravitar):
    name = read_gravitar.replace('.', '-')
    name = f'asteroids-{name}'

    clusters = eks.list_eks()

    assert name in clusters

    clusters = eks.list_eks(read_gravitar)

    assert name in clusters

    clusters = eks.list_eks('invalid')
    assert not clusters


def test_get_eks_status(cluster_name):
    assert 'ACTIVE' == eks.get_eks_status(cluster_name)['status']
    assert 'Error' in eks.get_eks_status('invalid')


def test_get_eks_nodegroup_status(cluster_name, nodegroup):
    assert 'ACTIVE' == eks.get_eks_nodegroup_status(cluster_name, nodegroup)['status']
    assert 'Error' in eks.get_eks_nodegroup_status(cluster_name, "invalid")
    assert 'Error' in eks.get_eks_nodegroup_status("", "invalid")
    assert 'Error' in eks.get_eks_nodegroup_status(cluster_name, "")


def test_info_eks_nodegroup(cluster_name, nodegroup):
    info = eks.info_eks_nodegroup(cluster_name, nodegroup)
    assert info['clusterName'] == cluster_name
    assert info['nodegroupName'] == nodegroup

    assert not eks.info_eks_nodegroup(cluster_name, "")
    assert not eks.info_eks_nodegroup("", nodegroup)
    assert not eks.info_eks_nodegroup(cluster_name, "invalid")


def test_eks(write_gravitar):
    res = eks.create_eks('test', write_gravitar)
    assert 'ACTIVE' == res['status']

    res = eks.create_eks_nodegroup('test', write_gravitar, 1, 't3.nano', 4)

    assert 'ACTIVE' == res['status']

    eks.delete_eks_nodegroup('test', write_gravitar)
    
    eks.delete_eks('test', write_gravitar)

