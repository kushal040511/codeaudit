"""Well-handled errors: no finding, every component 1.0."""

import logging

import httpx

logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Raised when the store can't be read."""


def read_config(path):
    try:
        with open(path) as handle:
            return handle.read()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise StorageError(path) from exc


def fetch_status(url):
    try:
        response = httpx.get(url, timeout=5)
    except httpx.HTTPError:
        logger.warning("status check failed for %s", url, exc_info=True)
        return None
    return response.status_code
