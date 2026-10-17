"""Compare scan findings with the previous completed scan for the same asset."""
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import ScanJob, Finding, ScanStatus


@dataclass
class FindingSignature:
    checker: str
    title: str
    evidence: str | None

    def key(self) -> tuple:
        return (self.checker, self.title, self.evidence or "")


def _signature(f: Finding) -> tuple:
    return FindingSignature(f.checker, f.title, f.evidence).key()


def get_previous_completed_scan(db: Session, asset_id: int, scan_type, before_scan_id: int) -> ScanJob | None:
    return (
        db.query(ScanJob)
        .filter(
            ScanJob.asset_id == asset_id,
            ScanJob.scan_type == scan_type,
            ScanJob.status == ScanStatus.completed,
            ScanJob.id != before_scan_id,
        )
        .order_by(ScanJob.completed_at.desc())
        .first()
    )


def find_new_findings(db: Session, current_scan: ScanJob) -> list[Finding]:
    """Return findings absent from the previous completed scan, if any."""
    previous = get_previous_completed_scan(
        db, current_scan.asset_id, current_scan.scan_type, current_scan.id
    )
    if previous is None:
        return []

    previous_signatures = {_signature(f) for f in previous.findings}
    return [f for f in current_scan.findings if _signature(f) not in previous_signatures]
