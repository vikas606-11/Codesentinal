"""Intentionally vulnerable demo file for CodeSentinel. Never use this code in production."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "admin@12345"
SECRET_TOKEN = "demo-token-not-a-real-secret"


@app.route("/user")
def get_user():
    name = request.args.get("name")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run("ping -c 1 " + host, shell=True)
    os.system("echo " + host)
    return "ok"


def load_blob(data):
    return pickle.loads(data)


def load_config(text):
    return yaml.load(text)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def fetch(url):
    return requests.get(url, verify=False)


def add_item(item, items=[]):
    items.append(item)
    return items


def risky():
    try:
        return 1 / 0
    except:
        pass


if __name__ == "__main__":
    app.run(debug=True)
