"""
Data models for windows-desktop-secure-secrets scanner.
Zero external dependencies, pure Python standard library.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    cwe: str
    owasp: str
    file_path: str
    line_number: int
    column: int
    snippet: str
    message: str
    remediation: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "snippet": self.snippet.strip(),
            "message": self.message.strip(),
            "remediation": self.remediation.strip(),
            "references": self.references,
        }


@dataclass
class ScanResult:
    target_path: str
    total_files_scanned: int
    total_findings: int
    findings: List[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "summary": {
                "total_files_scanned": self.total_files_scanned,
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "scan_duration_seconds": round(self.scan_duration_seconds, 3),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
