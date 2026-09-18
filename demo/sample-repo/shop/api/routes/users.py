from flask import Blueprint, jsonify, request

from shop.services import users

bp = Blueprint("users", __name__, url_prefix="/users")


@bp.get("/search")
def search():
    return jsonify(users.search(request.args.get("name", "")))
