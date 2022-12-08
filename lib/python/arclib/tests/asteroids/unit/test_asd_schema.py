import json
import pytest

from jsonschema import validate
from jsonschema.exceptions import ValidationError


def test_asd_schema(asd_schema, valid_asd, invalid_id_asd, invalid_format_asd):
    with open(valid_asd) as fp:
        valid_json = json.load(fp)

    with open(invalid_id_asd) as fp:
        invalid_id_json = json.load(fp)

    with open(invalid_format_asd) as fp:
        invalid_format_json = json.load(fp)
    
    with open(asd_schema) as fp:
        json_schema = json.load(fp)

    validate(instance=valid_json, schema=json_schema)
    with pytest.raises(ValidationError):
        validate(instance=invalid_id_json, schema=json_schema)

    with pytest.raises(ValidationError):
        validate(instance=invalid_format_json, schema=json_schema)

    valid_json['service'] = 'ab'
    with pytest.raises(ValidationError):
        validate(instance=valid_json, schema=json_schema)

    valid_json['service'] = 'abc'
    validate(instance=valid_json, schema=json_schema)

    valid_json['service'] = 'a234567890123456' 
    validate(instance=valid_json, schema=json_schema) 

    valid_json['service'] = 'a2345678901234567' 
    with pytest.raises(ValidationError):
        validate(instance=valid_json, schema=json_schema)
