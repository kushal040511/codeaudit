from app.db.session import session
from app.models.user import User


def find_user(user_id: int) -> User | None:
    return session.get(User, user_id)
