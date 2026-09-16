from pydantic import BaseModel, ConfigDict

from app.models import FixStatus, Severity, ValidationStatus


class DependencyInfo(BaseModel):
    ecosystem: str
    package: str
    installed_version: str
    advisory_id: str
    aliases: list[str] = []
    fixed_version: str | None = None
    fixed_versions: list[str] = []
    cvss_score: str | None = None


class MergedFinding(BaseModel):
    analyzer: str
    rule_id: str
    severity: Severity
    start_line: int | None = None
    message: str


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
    category: str | None
    # Other analyzers that reported the same issue.
    corroborated_by: list[str]
    merged_from: list[MergedFinding]
    dependency: DependencyInfo | None
    # Overall score points gained if this finding alone were fixed.
    score_impact: float | None = None
    fix_status: FixStatus | None = None
    fix_validation_status: ValidationStatus | None = None


class FindingPage(BaseModel):
    items: list[FindingRead]
    total: int
    page: int
    page_size: int
