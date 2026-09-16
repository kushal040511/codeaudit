from app.models.user import User


def list_users() -> list[User]:
    return User.all()
