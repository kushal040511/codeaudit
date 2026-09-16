from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pkg.e import E


class D:
    child: "E | None" = None
