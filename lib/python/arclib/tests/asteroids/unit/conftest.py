import os
import pytest


@pytest.fixture
def dummy_asteroid_file():
    return "/tmp/dummyasteroid.json"


@pytest.fixture
def valid_asteroid_file():
    return "misc/asteroid-examples/testasteroid.json"


@pytest.fixture
def invalid_asteroid_file():
    return "misc/asteroid-examples/invalid.json"


@pytest.fixture
def invalid_asteroid_id_file():
    return "misc/asteroid-examples/invalid_id.json"


@pytest.fixture
def aws_credentials():
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing' 
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing' 
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-2'


@pytest.fixture
def s3_valid_asteroid():
    return "asteroid/testasteroid/latest/latest.json"


@pytest.fixture
def s3_valid_asd():
    return "asd/nginxaarf/latest/latest.json"


@pytest.fixture
def valid_asd():
    return "misc/demo/nginxaarf.json"


@pytest.fixture
def invalid_id_asd():
    return "misc/asd-examples/nginx_invalid_id.json"


@pytest.fixture
def invalid_format_asd():
    return "misc/asd-examples/nginxaarf_invalid.json"


@pytest.fixture
def s3_missing_obj():
    return "testAsteroid/latest/latest.json"


@pytest.fixture
def asd_schema():
    return "asdschema.json"


@pytest.fixture
def dummyASD():
    return "misc/demo/nginxaarf.json"


@pytest.fixture
def test_json_string():
    return '{"firstName":"test", "lastName":"testing"}'
