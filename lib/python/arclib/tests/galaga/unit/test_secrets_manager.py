import pytest
from arclib import secrets_manager
from moto import mock_secretsmanager

@pytest.fixture
def secret_name_setup():
    return {
        'arcade_name': 'wet_dry_arcade.grv',
        'secret_name': 'galaga-test-name', 
        'secret_value': 'Welcome123!', 
    }

@pytest.fixture
def update_secrets_setup():
    return {
        'secret_value': '!321Welcome',
    }

@mock_secretsmanager
def test_setup(secret_name_setup):
    # Create Secret
    test_create = secrets_manager.create_secret(
        arcade_name=secret_name_setup['arcade_name'],
        name=secret_name_setup['secret_name'],
        secret_value=secret_name_setup['secret_value']
    )

    assert 'SecretName' in test_create
    assert 'SecretARN' in test_create


@mock_secretsmanager
def test_setup_and_update(secret_name_setup, update_secrets_setup):
    # Create Secret
    test_create = secrets_manager.create_secret(
        arcade_name=secret_name_setup['arcade_name'],
        name=secret_name_setup['secret_name'],
        secret_value=secret_name_setup['secret_value']
    )

    assert 'SecretName' in test_create
    assert 'SecretARN' in test_create

    # Update Secret
    test_update_secret = secrets_manager.update_secret(
        arcade_name=secret_name_setup['arcade_name'],
        name=secret_name_setup['secret_name'],
        secret_value=update_secrets_setup['secret_value']
    )
    
    # Make sure updated values match
    assert test_update_secret['SecretName'] == f"{secret_name_setup['arcade_name']}/{secret_name_setup['secret_name']}"
    # Make sure a ARN is present
    assert 'SecretARN' in test_update_secret

@mock_secretsmanager
def test_create_and_get(secret_name_setup):
    test_create = secrets_manager.create_secret(
        arcade_name=secret_name_setup['arcade_name'],
        name=secret_name_setup['secret_name'],
        secret_value=secret_name_setup['secret_value']
    )

    assert 'SecretName' in test_create
    assert 'SecretARN' in test_create

    # Get Secret
    test_get_value = secrets_manager.get_secret(
        arcade_name=secret_name_setup['arcade_name'],
        name=secret_name_setup['secret_name']
    )

    assert test_get_value == secret_name_setup['secret_value']


@mock_secretsmanager
def test_create_and_delete(secret_name_setup):
    test_create = secrets_manager.create_secret(
        arcade_name=secret_name_setup['arcade_name'],
        name=secret_name_setup['secret_name'],
        secret_value=secret_name_setup['secret_value']
    )

    assert 'SecretName' in test_create
    assert 'SecretARN' in test_create

    test_delete_secret = secrets_manager.delete_secret(
        arcade_name=secret_name_setup['arcade_name'],
        name=secret_name_setup['secret_name'],
        without_recovery=True
    )

    assert test_delete_secret['Name'] == f"{secret_name_setup['arcade_name']}/{secret_name_setup['secret_name']}"


