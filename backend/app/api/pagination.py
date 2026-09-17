"""Page/page_size pagination for list endpoints that return JSON arrays.

Bodies stay arrays; totals and navigation go in headers (`X-Total-Count`, `Link`), so
existing clients keep working while every list is bounded (MAX_PAGE_SIZE).
"""

from dataclasses import dataclass
from typing import Annotated, Any, TypeVar

from fastapi import Query, Request, Response
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

MAX_PAGE_SIZE = 100
T = TypeVar("T")


@dataclass(frozen=True)
class PageParams:
    page: int
    page_size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def page_params(
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
) -> PageParams:
    return PageParams(page, page_size)


def paginate(
    db: Session, statement: Select[Any], params: PageParams, request: Request, response: Response
) -> list[Any]:
    total = db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
    rows = list(db.execute(statement.offset(params.offset).limit(params.page_size)).all())
    set_page_headers(total, params, request, response)
    return rows


def set_page_headers(total: int, params: PageParams, request: Request, response: Response) -> None:
    response.headers["X-Total-Count"] = str(total)
    links = []
    last = max(1, -(-total // params.page_size))
    for rel, number in (
        ("first", 1),
        ("prev", params.page - 1),
        ("next", params.page + 1),
        ("last", last),
    ):
        if 1 <= number <= last and (rel not in ("prev", "next") or number != params.page):
            url = request.url.include_query_params(page=number, page_size=params.page_size)
            links.append(f'<{url}>; rel="{rel}"')
    if links:
        response.headers["Link"] = ", ".join(links)
