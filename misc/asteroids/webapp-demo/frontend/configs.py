#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

# A simple utility to provide an updated configs.json for secretsmanager
import base64
import json
import os
import sys

files = ['nginx.conf', 'mime.types', 'static/index.html',
         'static/api-calls.js', 'static/style.css', 'static/favicon.png']

resp = {}

static_dest = '/app/static'
nginx_dest = '/etc/nginx'

for file in files:
    file_obj = ''
    if not os.path.exists(file):
        # This should only happen once unless one of the files is actually missing!
        argv0dir = os.path.dirname(sys.argv[0])
        os.chdir(argv0dir)
        if not os.path.exists(file):
            print(f"Cannot find file: app.py")
            sys.exit(1)
    if file.endswith('.png'):
        file_obj = open(file, "rb")
    else:
        file_obj = open(file, "r")
    file_data = file_obj.read()
    file_obj.close()
    encode = ''
    if not file.endswith('.png'):
        encoded = base64.b64encode(file_data.encode('utf-8')).decode('utf-8')
    else:
        encoded = base64.b64encode(file_data).decode('utf-8')
    if file.startswith('static'):
        name = file.split('/')[-1]
        resp[name + ":" + static_dest] = encoded
    else:
        resp[file + ":" + nginx_dest] = encoded

with open('configs.json', 'w') as f:
    json.dump(resp, f)
