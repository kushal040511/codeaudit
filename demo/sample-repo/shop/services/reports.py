import os
import subprocess

import yaml


def export(fmt):
    # The format comes straight from the request body.
    subprocess.call("sqlite3 shop.db .dump > /tmp/export." + fmt, shell=True)
    return "/tmp/export." + fmt


def import_config(raw):
    try:
        return yaml.load(raw)
    except:
        return os.environ.get("DEFAULT_IMPORT", {})
