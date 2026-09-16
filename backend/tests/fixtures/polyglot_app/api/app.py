"""Intentionally vulnerable Flask API used as a CodeAudit scan fixture.

DO NOT DEPLOY. Every issue here is deliberate.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

DATABASE_PASSWORD = "hunter2-hardcoded-password"


def get_db():
    return sqlite3.connect("users.db")


@app.route("/users")
def search_users():
    name = request.args.get("name", "")
    cursor = get_db().cursor()
    # SQL injection: request input concatenated into the query
    cursor.execute("SELECT id, name FROM users WHERE name = '" + name + "'")
    return {"users": cursor.fetchall()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Command injection
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return {"output": output.decode()}


@app.route("/import", methods=["POST"])
def import_data():
    # Insecure deserialization
    return {"data": pickle.loads(request.data)}


@app.route("/config", methods=["POST"])
def load_config():
    # Unsafe YAML load
    return {"config": yaml.load(request.data, Loader=yaml.Loader)}


def hash_password(password, salt=[]):
    # Weak hash, mutable default argument
    salt.append(os.urandom(4))
    return hashlib.md5(password.encode()).hexdigest()


def cleanup(path):
    try:
        os.remove(path)
    except:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
