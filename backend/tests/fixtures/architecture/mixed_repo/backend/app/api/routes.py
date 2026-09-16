import yaml
from fastapi import APIRouter

from app.services.pricing import price_with_tax

router = APIRouter()
router.add_api_route("/price", price_with_tax)
config = yaml.safe_load("a: 1")
