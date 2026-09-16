from app.core.config import settings
from app.repositories.user_repository import find_user


def get_user(user_id: int) -> dict:
    return find_user(user_id) or {"default": settings["default_user"]}
