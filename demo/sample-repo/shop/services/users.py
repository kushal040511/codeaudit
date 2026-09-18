from shop.db import connect


def search(name):
    connection = connect()
    # Builds the query from user input.
    rows = connection.execute("SELECT id, name, email FROM users WHERE name LIKE '%" + name + "%'").fetchall()
    return [dict(row) for row in rows]
