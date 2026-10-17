"""Schedule recurring monitoring scans with APScheduler."""
import asyncio
import logging
from datetime import datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import MonitorSchedule, Asset
from app.orchestrator.scan_orchestrator import run_scan_job

logger = logging.getLogger("securescan.scheduler")

# Scheduler polling interval; schedules run at hour- or day-scale intervals.
TICK_INTERVAL_SECONDS = 60

_scheduler = AsyncIOScheduler()


async def _tick() -> None:
    db: Session = SessionLocal()
    try:
        now = datetime.utcnow()
        due = (
            db.query(MonitorSchedule)
            .filter(MonitorSchedule.is_active == True, MonitorSchedule.next_run_at <= now)  # noqa: E712
            .all()
        )
        for schedule in due:
            asset = db.query(Asset).filter(Asset.id == schedule.asset_id).first()

            if asset is not None and asset.is_demo:
                # Keep demo schedules current without scanning the reserved .example domain.
                schedule.last_run_at = now
                schedule.next_run_at = now + timedelta(hours=schedule.frequency_hours)
                db.commit()
                continue

            logger.info(
                "Monitoring: запускаю плановый скан asset_id=%s (schedule #%s)",
                schedule.asset_id, schedule.id,
            )
            # Reuse the same ScanJob model and orchestration path as manual scans.
            from app.models import ScanJob, ScanStatus  # Avoid an import cycle.

            scan_job = ScanJob(
                asset_id=schedule.asset_id,
                scan_type=schedule.scan_type,
                status=ScanStatus.queued,
            )
            db.add(scan_job)
            db.commit()
            db.refresh(scan_job)

            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(hours=schedule.frequency_hours)
            db.commit()

            # Run scans as background tasks so scheduler polling can continue.
            asyncio.create_task(run_scan_job(scan_job.id))
    finally:
        db.close()


def start_scheduler() -> None:
    if not _scheduler.running:
        _scheduler.add_job(_tick, "interval", seconds=TICK_INTERVAL_SECONDS, id="monitoring_tick")
        _scheduler.start()
        logger.info("Monitoring scheduler started (tick every %ss)", TICK_INTERVAL_SECONDS)


def stop_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Monitoring scheduler stopped")
