import pytest

from arclib import cloudmap


@pytest.fixture
def vpc_id():
    return 'vpc-00d0a8484df1f7d3b'


@pytest.fixture
def arcade_name():
    return 'puny_jam.grv'


def test_get_cloudmap_status(vpc_id, arcade_name):
    cloudmap.create_cloudmap_namespace(vpc_id, arcade_name) 
    
    status = cloudmap.get_cloudmap_status(arcade_name)

    assert status


def test_create_cloudmap_namespace(vpc_id, arcade_name):
    status = cloudmap.create_cloudmap_namespace(vpc_id, arcade_name) 
    assert status


def test_delete_cloudmap_namespace(vpc_id, arcade_name):
    cloudmap.create_cloudmap_namespace(vpc_id, arcade_name)

    status = cloudmap.delete_cloudmap_namespace(arcade_name)
    assert not status
