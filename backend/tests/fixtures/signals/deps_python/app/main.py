import os

import numpy  # imported but not declared anywhere
import requests
import yaml
from flask import Flask

app = Flask(__name__)


def load(path: str) -> dict:
    with open(os.path.join(path, "config.yaml")) as handle:
        return yaml.safe_load(handle)


def fetch(url: str) -> int:
    return requests.get(url, timeout=5).status_code + int(numpy.zeros(1)[0])
