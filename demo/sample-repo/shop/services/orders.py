from shop.db import connect
from shop.models.order import Order
from shop.services import billing


def get(order_id):
    row = connect().execute("SELECT * FROM orders WHERE id = %s" % order_id).fetchone()
    return Order.from_row(row).to_dict()


def pay(order_id, card_token):
    order = get(order_id)
    receipt = billing.charge(order, card_token)
    return {"order": order, "receipt": receipt}


def mark_paid(order_id):
    connect().execute("UPDATE orders SET status = 'paid' WHERE id = ?", (order_id,))
