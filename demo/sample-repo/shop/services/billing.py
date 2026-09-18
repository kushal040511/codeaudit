import requests

from shop.services import orders

PAYMENTS_URL = "http://payments.internal/charge"


def charge(order, card_token):
    response = requests.post(PAYMENTS_URL, json={"amount": order["total"], "token": card_token}, verify=False)
    if response.ok:
        orders.mark_paid(order["id"])
    return response.json()
