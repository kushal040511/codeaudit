from dataclasses import dataclass

from shop.api.routes.orders import ORDER_STATUSES


@dataclass
class Order:
    id: int
    total: float
    status: str

    @classmethod
    def from_row(cls, row):
        if row["status"] not in ORDER_STATUSES:
            raise ValueError(row["status"])
        return cls(row["id"], row["total"], row["status"])

    def to_dict(self):
        return {"id": self.id, "total": self.total, "status": self.status}
