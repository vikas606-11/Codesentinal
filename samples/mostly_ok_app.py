"""A mostly fine module with three small issues: expected score 83 (Good), gate PASS."""
import hashlib


def checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def parse(value):
    try:
        return int(value)
    except:
        return 0


def run(app):
    app.run(debug=True)
