from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app.db import get_db
from app.models import Asset, AssetCreate, AssetOut, VerificationMethod, User
from app.verification import verify_asset
from app.security import get_current_user

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (
        db.query(Asset)
        .filter(Asset.owner_id == current_user.id)
        .order_by(Asset.created_at.desc())
        .all()
    )


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    payload: AssetCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    existing = (
        db.query(Asset)
        .filter(Asset.owner_id == current_user.id, Asset.domain == payload.domain)
        .first()
    )
    if existing:
        raise HTTPException(409, "Вы уже зарегистрировали этот домен")

    asset = Asset(
        domain=payload.domain,
        owner_id=current_user.id,
        verification_token=Asset.generate_token(),
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _get_owned_asset(asset_id: int, db: Session, current_user: User) -> Asset:
    """Return 404 for missing or unowned assets to prevent enumeration."""
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.owner_id == current_user.id)
        .first()
    )
    if not asset:
        raise HTTPException(404, "Актив не найден")
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    return _get_owned_asset(asset_id, db, current_user)


@router.post("/{asset_id}/verify", response_model=AssetOut)
def verify(
    asset_id: int,
    method: VerificationMethod = VerificationMethod.dns_txt,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verify asset ownership; active scanning stays blocked until verified."""
    asset = _get_owned_asset(asset_id, db, current_user)

    ok = verify_asset(asset.domain, asset.verification_token, method)
    if ok:
        asset.is_verified = True
        asset.verification_method = method
        asset.verified_at = datetime.utcnow()
        db.commit()
        db.refresh(asset)
        return asset

    raise HTTPException(
        422,
        f"Токен верификации не найден методом '{method.value}'. "
        f"Разместите токен '{asset.verification_token}' и попробуйте снова.",
    )
