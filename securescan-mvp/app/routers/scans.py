from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Asset, ScanJob, ScanCreate, ScanOut, ScanStatus, ScanType, User
from app.orchestrator.scan_orchestrator import run_scan_job
from app.security import get_current_user
from app.ratelimit import SlidingWindowRateLimiter
from app.config import settings

router = APIRouter(prefix="/scans", tags=["scans"])

_scan_rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.scan_rate_limit_per_hour, window_seconds=3600
)


def _get_owned_asset(asset_id: int, db: Session, current_user: User) -> Asset:
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.owner_id == current_user.id)
        .first()
    )
    if not asset:
        raise HTTPException(404, "Актив не найден")
    return asset


@router.post("", response_model=ScanOut, status_code=202)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _scan_rate_limiter.check(str(current_user.id))

    asset = _get_owned_asset(payload.asset_id, db, current_user)

    if payload.scan_type == ScanType.active and not asset.is_verified:
        raise HTTPException(
            403,
            "Активное сканирование требует верифицированного владения активом. "
            "Сначала пройдите POST /assets/{id}/verify.",
        )

    scan_job = ScanJob(asset_id=asset.id, scan_type=payload.scan_type, status=ScanStatus.queued)
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    # The background job opens its own database session.
    background_tasks.add_task(run_scan_job, scan_job.id)

    return scan_job


@router.get("", response_model=list[ScanOut])
def list_scans(
    asset_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    _get_owned_asset(asset_id, db, current_user)
    return (
        db.query(ScanJob)
        .filter(ScanJob.asset_id == asset_id)
        .order_by(ScanJob.created_at.desc())
        .all()
    )


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    return _get_owned_scan(scan_id, db, current_user)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Request cancellation; the orchestrator stops the active scanner between steps."""
    scan_job = _get_owned_scan(scan_id, db, current_user)

    if scan_job.status not in (ScanStatus.queued, ScanStatus.running):
        raise HTTPException(
            409,
            f"Скан в статусе '{scan_job.status.value}' нельзя отменить — он уже завершён.",
        )

    scan_job.cancel_requested = True
    db.commit()
    db.refresh(scan_job)
    return scan_job


def _get_owned_scan(scan_id: int, db: Session, current_user: User) -> ScanJob:
    scan_job = (
        db.query(ScanJob)
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(ScanJob.id == scan_id, Asset.owner_id == current_user.id)
        .first()
    )
    if not scan_job:
        raise HTTPException(404, "Скан не найден")
    return scan_job
