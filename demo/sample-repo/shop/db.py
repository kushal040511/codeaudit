import sqlite3

from shop.config import Config


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(Config.DATABASE)
    connection.row_factory = sqlite3.Row
    return connection
