import pytest

from arclib import msk


@pytest.fixture
def cluster_name():
    return 'test-dampred-grv'


@pytest.fixture
def configuration():
    return 'test-dampred-grv'


@pytest.fixture
def write_gravitar():
    return 'damp_red.grv'


def test_create_msk(write_gravitar):
    res = msk.create_msk_configuration('test', write_gravitar, '2.6.2', '')
    assert 'ACTIVE' == res['State']

    res = msk.create_msk('test', write_gravitar, 'kafka.t3.small', 1, 1, '2.6.2')
    assert 'ACTIVE' == res['State']

    info = msk.get_msk_status(cluster_name)
    assert info['ClusterName'] == cluster_name
    assert 'ACTIVE' == msk.get_msk_status(cluster_name)['State']
    assert {} == msk.get_msk_status('invalid')

    assert 'ACTIVE' == msk.get_msk_configuration(cluster_name)['State']
    assert {} == msk.get_msk_configuration("invalid")

    status = msk.delete_msk('test', write_gravitar)

    status = msk.delete_msk_configuration('test', write_gravitar)
