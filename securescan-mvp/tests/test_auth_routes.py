"""Tests for the authenticated-only account access routes."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.config import settings
from app.models import GUEST_USER_EMAIL, User, UserLogin, UserOut
from app.routers.auth import login, register, router
from app.security import get_current_user, get_current_user_flexible, hash_password
from fastapi import HTTPException


def test_only_login_and_current_user_routes_are_exposed():
    paths = {route.path for route in router.routes}

    assert "/auth/login" in paths
    assert "/auth/me" in paths
    assert ("/auth/register" in paths) is settings.public_registration_enabled


def test_open_mode_resolves_anonymous_user(monkeypatch):
    monkeypatch.setattr(settings, "auth_required", False)
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = testing_session()
    try:
        db.add(User(email=GUEST_USER_EMAIL, hashed_password=hash_password("unused-test-password")))
        db.commit()

        guest = get_current_user(credentials=None, db=db)
        report_guest = get_current_user_flexible(token=None, credentials=None, db=db)
        guest_out = UserOut.model_validate(guest)

        assert guest.email == GUEST_USER_EMAIL
        assert guest.is_guest is True
        assert report_guest.id == guest.id
        assert guest_out.is_guest is True
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_auth_required_mode_rejects_anonymous_user(monkeypatch):
    monkeypatch.setattr(settings, "auth_required", True)

    try:
        get_current_user(credentials=None, db=None)
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("Anonymous access should be rejected when auth is required")


def test_seeded_account_can_sign_in_with_its_password():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = testing_session()
    try:
        db.add(User(email="operator@example.invalid", hashed_password=hash_password("private-test-password")))
        db.commit()

        token = login(
            UserLogin(email="operator@example.invalid", password="private-test-password"),
            db,
        )

        assert token.access_token
        assert token.token_type == "bearer"
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()