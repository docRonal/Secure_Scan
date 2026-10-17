"""Execute scan jobs and persist their findings and status."""
import asyncio
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Asset, ScanJob, Finding, ScanStatus, ScanType, Severity
from app.scanners.base import ScanCancelled, ScanTimedOut
from app.scanners.passive import PASSIVE_SCANNERS
from app.scanners.active import ACTIVE_SCANNERS
from app.monitoring.diff import find_new_findings
from app.notifications.notifier import active_notifier, NotificationEvent

logger = logging.getLogger("securescan.orchestrator")


def _make_should_cancel(scan_job_id: int):
    """Return a cancellation callback that reads job state in a fresh session."""
    def should_cancel() -> bool:
        check_db = SessionLocal()
        try:
            job = check_db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            return bool(job and job.cancel_requested)
        finally:
            check_db.close()
    return should_cancel


def _make_progress_reporter(scan_job_id: int):
    """Return a callback that writes progress using its own database session."""
    def report_progress(percent: int, step: str) -> None:
        check_db = SessionLocal()
        try:
            job = check_db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if job is not None:
                job.progress_percent = max(0, min(100, percent))
                job.current_step = step
                check_db.commit()
        finally:
            check_db.close()
    return report_progress


async def run_scan_job(scan_job_id: int) -> None:
    """Run a background scan job in an independent database session."""
    db: Session = SessionLocal()
    try:
        await _execute(db, scan_job_id)
    finally:
        db.close()


async def _execute(db: Session, scan_job_id: int) -> None:
    scan_job: ScanJob | None = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
    if scan_job is None:
        logger.error("Scan job %s not found", scan_job_id)
        return

    asset: Asset = scan_job.asset

    # Active scans are restricted to verified assets.
    if scan_job.scan_type == ScanType.active and not asset.is_verified:
        scan_job.status = ScanStatus.blocked_unverified
        scan_job.error_message = (
            "Активное сканирование заблокировано: владение активом не верифицировано. "
            "Пройдите верификацию через /assets/{id}/verify перед активным сканом."
        )
        db.commit()
        return

    scan_job.status = ScanStatus.running
    scan_job.started_at = datetime.utcnow()
    scan_job.progress_percent = 0
    db.commit()

    try:
        loop = asyncio.get_running_loop()

        if scan_job.scan_type == ScanType.passive:
            total = len(PASSIVE_SCANNERS)
            for i, scanner_cls in enumerate(PASSIVE_SCANNERS):
                db.refresh(scan_job)
                if scan_job.cancel_requested:
                    _mark_cancelled(db, scan_job)
                    return

                scanner = scanner_cls()
                scan_job.current_step = f"Проверка: {scanner.name}"
                db.commit()

                # Run blocking HTTP checks outside the FastAPI event loop.
                findings = await loop.run_in_executor(None, scanner.run, asset.domain)
                _persist_findings(db, scan_job.id, findings)

                scan_job.progress_percent = int(((i + 1) / total) * 100)
                db.commit()

        elif scan_job.scan_type == ScanType.active:
            if not ACTIVE_SCANNERS:
                raise RuntimeError(
                    "Реестр ACTIVE_SCANNERS пуст: в MVP не подключён ни один "
                    "движок активного сканирования (см. app/scanners/active/__init__.py)."
                )
            should_cancel = _make_should_cancel(scan_job_id)
            report_progress = _make_progress_reporter(scan_job_id)
            for plugin_cls in ACTIVE_SCANNERS:
                plugin = plugin_cls()
                findings = await loop.run_in_executor(
                    None, plugin.run, asset.domain, asset.verification_token,
                    should_cancel, report_progress,
                )
                _persist_findings(db, scan_job.id, findings)

        scan_job.status = ScanStatus.completed
        scan_job.progress_percent = 100
        scan_job.completed_at = datetime.utcnow()
        db.commit()

    except ScanCancelled as exc:
        if exc.partial_findings:
            _persist_findings(db, scan_job.id, exc.partial_findings)
        db.refresh(scan_job)
        _mark_cancelled(db, scan_job, message=str(exc))
        return

    except ScanTimedOut as exc:
        if exc.partial_findings:
            _persist_findings(db, scan_job.id, exc.partial_findings)
        db.refresh(scan_job)
        scan_job.status = ScanStatus.failed
        scan_job.error_message = str(exc)
        scan_job.completed_at = datetime.utcnow()
        db.commit()
        logger.warning("Scan job %s timed out with %d partial findings", scan_job_id, len(exc.partial_findings))
        return

    except Exception as exc:  # noqa: BLE001 — прототип: логируем и помечаем как failed
        logger.exception("Scan job %s failed", scan_job_id)
        scan_job.status = ScanStatus.failed
        scan_job.error_message = str(exc)
        db.commit()
        return

    # Notification failures must not change an already completed scan to failed.
    try:
        _check_and_notify_new_findings(db, scan_job)
    except Exception:  # noqa: BLE001 — сбой уведомления не должен ронять скан
        logger.exception("Notification failed for scan job %s (scan itself completed OK)", scan_job_id)


def _mark_cancelled(db: Session, scan_job: ScanJob, message: str = "Скан остановлен пользователем.") -> None:
    scan_job.status = ScanStatus.cancelled
    scan_job.error_message = message
    scan_job.completed_at = datetime.utcnow()
    db.commit()
    logger.info("Scan job %s cancelled by user", scan_job.id)


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _check_and_notify_new_findings(db: Session, scan_job: ScanJob) -> None:
    """Notify when a completed scan contains findings absent from its predecessor."""
    db.refresh(scan_job)  # подтянуть связанные findings свежими из БД
    new_findings = find_new_findings(db, scan_job)
    if not new_findings:
        return

    highest = max(new_findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value))
    event = NotificationEvent(
        asset_domain=scan_job.asset.domain,
        scan_id=scan_job.id,
        new_findings_count=len(new_findings),
        highest_new_severity=highest.severity.value,
        summary=f"Новая находка: {highest.title}",
    )
    active_notifier.send(event)


def _persist_findings(db: Session, scan_job_id: int, findings) -> None:
    for f in findings:
        db.add(
            Finding(
                scan_id=scan_job_id,
                checker=f.checker,
                title=f.title,
                severity=Severity(f.severity),
                description=f.description,
                recommendation=f.recommendation,
                owasp_category=f.owasp_category,
                cwe_id=f.cwe_id,
                evidence=f.evidence,
            )
        )
    db.commit()
