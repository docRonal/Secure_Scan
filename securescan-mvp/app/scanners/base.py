"""Shared scanner interfaces and finding severity calibration.

Severity should reflect practical exploitability in current environments, not
the historical reputation of a vulnerability class. Use low for weaknesses
requiring additional conditions, medium for materially exploitable issues,
high for currently practical exploitation, and critical for trivial severe impact.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class ScanInterrupted(Exception):
    """Base class for interrupted scans that may carry partial findings."""

    def __init__(self, message: str, partial_findings: list["ScanFinding"] | None = None):
        super().__init__(message)
        self.partial_findings: list["ScanFinding"] = partial_findings or []


class ScanCancelled(ScanInterrupted):
    """The user cancelled the scan."""


class ScanTimedOut(ScanInterrupted):
    """The scan exceeded its configured time limit."""


@dataclass
class ScanFinding:
    checker: str
    title: str
    severity: str            # "info" | "low" | "medium" | "high" | "critical"
    description: str
    recommendation: str | None = None
    owasp_category: str | None = None
    cwe_id: str | None = None
    evidence: str | None = None


class BaseScanner(ABC):
    """Base interface for scanner implementations."""

    #: Machine-readable identifier stored as Finding.checker.
    name: str = "base"

    @abstractmethod
    def run(self, domain: str) -> list[ScanFinding]:
        """Run a check and return any findings."""
        raise NotImplementedError
