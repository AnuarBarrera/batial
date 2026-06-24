from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class ScanScope:
    target_host: str
    log_files: list[str] = field(default_factory=list)
    code_directory: Optional[str] = None
    time_range_hours: int = 24
    analysis_types: list[str] = field(default_factory=list)
    email_report_to: Optional[str] = None

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # "Critical" | "High" | "Medium" | "Low"
    evidence: str
    recommendation: str
    tool: str = ""
    status: str = ""           # "" = activo, "accepted" = aceptado formalmente
    accepted_reason: str = ""

@dataclass
class SecurityReport:
    findings: list[Finding] = field(default_factory=list)
    scope: Optional[ScanScope] = None
    generated_at: Optional[datetime] = None
    analysis_text: str = ""
    next_steps: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        active = [f for f in self.findings if f.status != "accepted"]
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in active:
            if f.severity in counts:
                counts[f.severity] += 1
        return {"total": len(active), **counts}
