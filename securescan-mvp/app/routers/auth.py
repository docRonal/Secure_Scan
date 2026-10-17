from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import User, UserCreate, UserLogin, UserOut, Token
from app.security import hash_password, verify_password, create_access_token, get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


def register(payload: UserCreate, db: Session = Depends(get_db)):
    if not settings.public_registration_enabled:
        raise HTTPException(404, "Public registration is disabled")

    existing = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing:
        raise HTTPException(409, "Пользователь с таким email уже зарегистрирован")

    user = User(email=payload.email.lower(), hashed_password=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return Token(access_token=create_access_token(user.id))


if settings.public_registration_enabled:
    router.add_api_route("/register", register, methods=["POST"], response_model=Token, status_code=201)


@router.post("/login", response_model=Token)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        # Use the same response for unknown emails and incorrect passwords to
        # prevent account enumeration.
        raise HTTPException(401, "Неверный email или пароль")

    return Token(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user
