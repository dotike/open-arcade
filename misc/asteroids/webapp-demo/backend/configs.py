#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

import json
import base64
import os
import sys


json_dict = {}
file = "app.py"
if not os.path.exists(file):
    argv0dir = os.path.dirname(sys.argv[0])
    os.chdir(argv0dir)
    if not os.path.exists(file):
        print(f"Cannot find file: app.py")
        sys.exit(1)
data = ''
with open(file, 'r') as f:
    data = base64.b64encode(f.read().encode('utf-8')).decode('utf-8')
json_dict[file + ":/usr/src/app"] = data
config_file = 'configs.json'
if not os.path.exists(config_file):
    print(f"Cannot find file: configs.json")
    sys.exit(1)
# TODO: make it into a function and add requirements.txt
with open(config_file, 'w') as f:
    json.dump(json_dict, f)
