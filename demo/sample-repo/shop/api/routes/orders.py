from flask import Blueprint, jsonify, request

from shop.services import orders, reports

bp = Blueprint("orders", __name__, url_prefix="/orders")

ORDER_STATUSES = ("pending", "paid", "shipped")


@bp.get("/<int:order_id>")
def get_order(order_id: int):
    return jsonify(orders.get(order_id))


@bp.post("/<int:order_id>/pay")
def pay(order_id: int):
    return jsonify(orders.pay(order_id, request.json["card_token"]))


@bp.post("/export")
def export():
    return jsonify({"file": reports.export(request.json["format"])})


@bp.post("/import")
def import_orders():
    return jsonify(reports.import_config(request.data))
