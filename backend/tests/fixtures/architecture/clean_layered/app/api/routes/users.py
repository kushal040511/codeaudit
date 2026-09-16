from app.services.user_service import get_user

router = {"GET /users/{id}": get_user}
