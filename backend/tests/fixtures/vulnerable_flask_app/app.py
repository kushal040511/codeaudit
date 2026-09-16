"""Intentionally vulnerable Flask app used as a CodeAudit scan fixture.

DO NOT DEPLOY. Every issue here is deliberate.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)

# Hardcoded secrets
app.config["SECRET_KEY"] = "dev-secret-key-do-not-use-in-prod"
DATABASE_PASSWORD = "hunter2-hardcoded-password"


def get_db():
    return sqlite3.connect("users.db")


@app.route("/users")
def search_users():
    name = request.args.get("name", "")
    cursor = get_db().cursor()
    # SQL injection: request input concatenated into the query
    cursor.execute("SELECT id, name, email FROM users WHERE name = '" + name + "'")
    return {"users": cursor.fetchall()}


@app.route("/users/<user_id>")
def get_user(user_id):
    # SQL injection via f-string
    query = f"SELECT id, name, email FROM users WHERE id = {user_id}"
    return {"user": get_db().execute(query).fetchone()}


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
