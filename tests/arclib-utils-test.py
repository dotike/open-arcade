#!/usr/bin/env python3

# Run with the following command line. Set the PYTHONPATH to match your arcade dir.
# env PYTHONPATH="/path/to/arcade/lib/python/arclib" tests/arclib-utils-test.py

import os
import sys
from arclib.common import str_to_bool as str_to_bool

test_vars = {
    'true': True,
    'false': False,
    'trUE': True,
    'faLsE': False,
    '1': True,
    '0': False,
    'yes': True,
    'no': False,
    'on': True,
    'off': False,
    'xyz': True,
    '': False,
   }


passing=0
count=0

for val in test_vars.keys():
    os.environ['XX'] = val
    bval = str_to_bool(os.getenv('XX'))
    print (f"String: '{val}', Expected result: '" + str(test_vars[val]) + f"', Returned: '{bval}'")
    count += 1
    if bval == test_vars[val]:
        passing += 1

result = "Success"
failed = count - passing
if failed:
    result = "Failed"
print (f"# Tests({count}): Result {result}: {passing} test(s) passed, {failed} test(s) failed.")
