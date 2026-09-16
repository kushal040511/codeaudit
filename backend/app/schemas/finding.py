from pydantic import BaseModel, ConfigDict

from app.models import Severity


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analyzer: str
    rule_id: str
    severity: Severity
    file_path: str
    start_line: int
    end_line: int
    message: str
    code_snippet: str | None


class FindingPage(BaseModel):
    items: list[FindingRead]
    total: int
    page: int
    page_size: int
