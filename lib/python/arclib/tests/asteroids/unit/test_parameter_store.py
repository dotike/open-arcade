#!/usr/bin/env python3

import pytest
from arclib import parameter_store
from moto import mock_ssm

@pytest.fixture
def parameter_store_setup():
    return {
        'arcade_name': 'wet_sea.grv',
        'parameter_name': 'test/path',
        'parameter_value': 'Welcome123'
    }


@mock_ssm
def test_setup_ps_securestring(parameter_store_setup):
    #Create Parameter Plain Text
    test_create = parameter_store.put_parameter(
        arcade_name=parameter_store_setup['arcade_name'], 
        parameter_name=parameter_store_setup['parameter_name'],
        parameter_value=parameter_store_setup['parameter_value'],
        data_type='SecureString'
    )

    assert 200 == test_create['ResponseMetadata']['HTTPStatusCode']


@mock_ssm
def test_get_ps_securestring(parameter_store_setup):
    #Create Parameter Plain Text
    test_create = parameter_store.put_parameter(
        arcade_name=parameter_store_setup['arcade_name'], 
        parameter_name=parameter_store_setup['parameter_name'],
        parameter_value=parameter_store_setup['parameter_value'],
        data_type='SecureString'
    )

    assert 200 == test_create['ResponseMetadata']['HTTPStatusCode']

    get_p_value = parameter_store.get_parameter(
        arcade_name=parameter_store_setup['arcade_name'],
        parameter_name=parameter_store_setup['parameter_name'],
        decryption=True
    )
    # Check and see if the value suppied at create is the value returned
    assert parameter_store_setup['parameter_value'] in get_p_value['Value']

@mock_ssm
def test_setup_ps_string(parameter_store_setup):
    #Create Parameter Plain Text
    test_create = parameter_store.put_parameter(
        arcade_name=parameter_store_setup['arcade_name'], 
        parameter_name=parameter_store_setup['parameter_name'],
        parameter_value=parameter_store_setup['parameter_value'],
        data_type='String'
    )

    assert 200 == test_create['ResponseMetadata']['HTTPStatusCode']

@mock_ssm
def test_ps_string_get(parameter_store_setup):
    #Create Parameter Plain Text
    test_create = parameter_store.put_parameter(
        arcade_name=parameter_store_setup['arcade_name'], 
        parameter_name=parameter_store_setup['parameter_name'],
        parameter_value=parameter_store_setup['parameter_value'],
        data_type='String'
    )

    assert 200 == test_create['ResponseMetadata']['HTTPStatusCode']

    # Get Value

    get_p_value = parameter_store.get_parameter(
        arcade_name=parameter_store_setup['arcade_name'],
        parameter_name=parameter_store_setup['parameter_name']
    )
    # Check and see if the value suppied at create is the value returned
    assert parameter_store_setup['parameter_value'] in get_p_value['Value']


@mock_ssm
def test_ps_string_delete(parameter_store_setup):
    #Create Parameter Plain Text
    test_create = parameter_store.put_parameter(
        arcade_name=parameter_store_setup['arcade_name'], 
        parameter_name=parameter_store_setup['parameter_name'],
        parameter_value=parameter_store_setup['parameter_value'],
        data_type='String'
    )

    assert 200 == test_create['ResponseMetadata']['HTTPStatusCode']

    test_delete = parameter_store.delete_parameter(arcade_name=parameter_store_setup['arcade_name'], 
                                                    parameter_name=parameter_store_setup['parameter_name'])

    assert 200 == test_delete['ResponseMetadata']['HTTPStatusCode']
