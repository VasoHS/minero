from pydantic import BaseModel, Field
from typing import List, Optional

class Finding(BaseModel):
    rule_id: str
    severity: Optional[str] = None
    message: str
    file: str
    start_line: Optional[int] = None

class RepositoryResult(BaseModel):
    name: str
    url: str
    status: str # "analyzed", "clone_failed", "unsupported", "db_failed", "analyze_failed", "invalid_name"
    languages: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)

class Summary(BaseModel):
    repositories: int = 0
    analyzed: int = 0
    failed: int = 0
    unsupported: int = 0
    findings: int = 0

class OrganizationReport(BaseModel):
    organization: str
    summary: Summary
    repositories: List[RepositoryResult] = Field(default_factory=list)
