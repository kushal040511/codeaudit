from app.models.order import Order

# Layer skip: the route talks to the model directly instead of going through a service.
router = {"GET /orders": lambda: Order.all()}
