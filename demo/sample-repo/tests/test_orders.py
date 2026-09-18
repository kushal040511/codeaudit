from shop.models.order import Order


def test_order_round_trip():
    order = Order(1, 9.5, "paid")
    assert order.to_dict() == {"id": 1, "total": 9.5, "status": "paid"}
