from pydantic import BaseModel, Field
from typing import Dict, List, Optional

class Finding(BaseModel):
    rule_id: str
    severity: Optional[str] = None
    message: str
    file: str
    start_line: Optional[int] = None

class SbomResult(BaseModel):
    # "generated": SBOM con componentes; "no_components": éxito sin componentes;
    # "failed": error de Syft; "skipped": no solicitado.
    status: str = "skipped"
    components: int = 0
    syft_version: Optional[str] = None
    generated_at: Optional[str] = None
    file: Optional[str] = None

class Vulnerability(BaseModel):
    """Una coincidencia de vulnerabilidad reportada por Grype."""
    id: str
    severity: Optional[str] = None
    package: str
    version: Optional[str] = None
    type: Optional[str] = None
    fixed_version: Optional[str] = None
    namespace: Optional[str] = None

class VulnResult(BaseModel):
    # "scanned": Grype terminó y encontró una o más vulnerabilidades;
    # "no_vulnerabilities": éxito sin hallazgos; "failed": error de Grype;
    # "skipped": no solicitado.
    status: str = "skipped"
    total: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    grype_version: Optional[str] = None
    generated_at: Optional[str] = None
    file: Optional[str] = None

class RepositoryResult(BaseModel):
    name: str
    full_name: Optional[str] = None
    url: str
    commit: Optional[str] = None
    # "analyzed", "clone_failed", "unsupported", "db_failed", "analyze_failed",
    # "invalid_name", "cloned", "scanned"
    status: str
    languages: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    sbom: SbomResult = Field(default_factory=SbomResult)
    vulnerabilities: VulnResult = Field(default_factory=VulnResult)

class Summary(BaseModel):
    repositories: int = 0
    analyzed: int = 0
    failed: int = 0
    unsupported: int = 0
    findings: int = 0
    sboms_generated: int = 0
    sboms_failed: int = 0
    components: int = 0
    vulns_scanned: int = 0
    vulns_failed: int = 0
    vulnerabilities: int = 0
    vulns_critical: int = 0
    vulns_high: int = 0
    vulns_medium: int = 0
    vulns_low: int = 0

class OrganizationReport(BaseModel):
    organization: str
    summary: Summary
    repositories: List[RepositoryResult] = Field(default_factory=list)
