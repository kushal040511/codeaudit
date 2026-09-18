"""Error-handling fixture: every Python rule, plus handled cases that must not be flagged."""

import logging
import subprocess

import requests

logger = logging.getLogger(__name__)


def bare():
    try:
        risky()
    except:  # bare-except
        pass


def swallowed():
    try:
        risky()
    except Exception:  # swallowed-broad-except
        pass


def swallowed_ellipsis():
    try:
        risky()
    except (ValueError, BaseException):  # swallowed-broad-except
        ...


def ignored(path):
    try:
        return int(path)
    except ValueError as exc:  # exception-ignored (bound name unused)
        return 0


def printed():
    try:
        risky()
    except RuntimeError:  # exception-ignored (print is not logging)
        print("failed")


def large():
    try:
        a = 1
        a = 2
        a = 3
        a = 4
        a = 5
        a = 6
        a = 7
        a = 8
        a = 9
        a = 10
        a = 11
        a = 12
        a = 13
        a = 14
        a = 15
        a = 16
        a = 17
        a = 18
        a = 19
        a = 20
        a = 21
        a = 22
        a = 23
        a = 24
        a = 25
        a = 26
    except Exception:  # broad-except-large-block (logged, so nothing else)
        logger.exception("large block failed")


# --- handled correctly: none of these may be flagged


def reraised():
    try:
        risky()
    except OSError:
        cleanup()
        raise


def logged():
    try:
        risky()
    except Exception:
        logger.warning("risky failed", exc_info=True)


def uses_name():
    try:
        risky()
    except ValueError as exc:
        return {"error": str(exc)}


def eafp(mapping):
    try:
        return mapping["key"]
    except KeyError:
        return None


def io_calls(url):
    requests.get(url)  # I/O, unwrapped
    with open("data.txt") as handle:  # I/O, unwrapped
        handle.read()
    try:
        subprocess.run(["ls"], check=True)  # I/O, wrapped
    except subprocess.CalledProcessError:
        logger.error("ls failed")
        raise


def risky():
    return None


def cleanup():
    return None
