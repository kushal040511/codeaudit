import json

from . import utils
from ..models import Product


def price_with_tax(product: Product) -> str:
    return json.dumps(utils.round_money(product.price * 1.2))
