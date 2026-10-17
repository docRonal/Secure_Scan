from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import (
    Asset, MonitorSchedule, MonitorScheduleCreate, MonitorScheduleUpdate,
    MonitorScheduleOut, ScanType, User,
)
from app.security import get_current_user

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


def _get_owned_asset(asset_id: int, db: Session, current_user: User) -> Asset:
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.owner_id == current_user.id)
        .first()
    )
    if not asset:
        raise HTTPException(404, "Актив не найден")
    return asset


def _get_owned_schedule(schedule_id: int, db: Session, current_user: User) -> MonitorSchedule:
    schedule = (
        db.query(MonitorSchedule)
        .join(Asset, MonitorSchedule.asset_id == Asset.id)
        .filter(MonitorSchedule.id == schedule_id, Asset.owner_id == current_user.id)
        .first()
    )
    if not schedule:
        raise HTTPException(404, "Расписание не найдено")
    return schedule


@router.post("", response_model=MonitorScheduleOut, status_code=201)
def create_schedule(
    payload: MonitorScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    asset = _get_owned_asset(payload.asset_id, db, current_user)

    if payload.scan_type == ScanType.active and not asset.is_verified:
        raise HTTPException(
            403,
            "Непрерывный мониторинг с активным сканированием требует "
            "верифицированного владения активом.",
        )

    schedule = MonitorSchedule(
        asset_id=asset.id,
        scan_type=payload.scan_type,
        frequency_hours=payload.frequency_hours,
        next_run_at=datetime.utcnow() + timedelta(hours=payload.frequency_hours),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


@router.get("", response_model=list[MonitorScheduleOut])
def list_schedules(
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(MonitorSchedule).join(Asset, MonitorSchedule.asset_id == Asset.id).filter(
        Asset.owner_id == current_user.id
    )
    if asset_id is not None:
        query = query.filter(MonitorSchedule.asset_id == asset_id)
    return query.order_by(MonitorSchedule.created_at.desc()).all()


@router.patch("/{schedule_id}", response_model=MonitorScheduleOut)
def update_schedule(
    schedule_id: int,
    payload: MonitorScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    schedule = _get_owned_schedule(schedule_id, db, current_user)

    if payload.is_active is not None:
        schedule.is_active = payload.is_active
    if payload.frequency_hours is not None:
        schedule.frequency_hours = payload.frequency_hours
        schedule.next_run_at = datetime.utcnow() + timedelta(hours=payload.frequency_hours)

    db.commit()
    db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(
    schedule_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    schedule = _get_owned_schedule(schedule_id, db, current_user)
    db.delete(schedule)
    db.commit()
