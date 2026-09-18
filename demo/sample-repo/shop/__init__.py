from flask import Flask

from shop.api.routes.orders import bp as orders_bp
from shop.api.routes.users import bp as users_bp
from shop.config import Config


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    app.register_blueprint(orders_bp)
    app.register_blueprint(users_bp)
    return app
