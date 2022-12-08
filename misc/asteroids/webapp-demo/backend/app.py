#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

from flask import Flask, make_response, request, redirect
from urllib.parse import urlparse

import json
import os

app = Flask(__name__)

#@app.route("/")
#def demo_app():
#    # return "<center> This is the Demo App </center>"
#    return redirect(request.host_url, 302)

# ENV VARS 
@app.route("/env", methods=['GET'])
def getEnv():
    env = dict(os.environ)
    resp = make_response(json.dumps(env), 200)
    resp.headers.add("Access-Control-Allow-Origin", "*")
    return resp

# vars inside /etc/arcade/configs
@app.route("/config", methods=['GET'])
def getConfig():
    conf_dict = {}
    try:
        conf_dir = os.listdir("/etc/arcade/configs")
        conf_dict["configs"] = conf_dir
    except:
        array = ["No conf files found there", "But they would show up here"]
        conf_dict["configs"] = array
    resp = make_response(json.dumps(conf_dict), 200)
    resp.headers.add("Access-Control-Allow-Origin", "*")
    return resp

if __name__ == "__main__":
    os.system('pip install -r requirements.txt')
    app.run(debug=True,host="0.0.0.0", port=8080)
