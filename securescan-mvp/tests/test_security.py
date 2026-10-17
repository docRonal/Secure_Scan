"""Tests for password hashing and JWT authentication helpers."""
import time

import pytest
from fastapi import HTTPException

from app.security import (
    hash_password, verify_password, create_access_token, decode_access_token,
)


def test_password_hash_roundtrip():
    hashed = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", hashed) is True


def test_wrong_password_rejected():
    hashed = hash_password("correct-horse-battery-staple")
    assert verify_password("wrong-password", hashed) is False


def test_hash_is_salted_differently_each_time():
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2, "Hashes should differ because each password uses a unique salt."
    assert verify_password("same-password", h1) is True
    assert verify_password("same-password", h2) is True


def test_verify_rejects_malformed_hash():
    assert verify_password("anything", "not-a-valid-hash-format") is False
    assert verify_password("anything", "pbkdf2_sha256$1$not-hex$deadbeef") is False
    assert verify_password("anything", "pbkdf2_sha256$0$00$deadbeef") is False


def test_jwt_roundtrip():
    token = create_access_token(user_id=42)
    assert decode_access_token(token) == 42


def test_jwt_rejects_tampered_token():
    token = create_access_token(user_id=42)
    tampered = token[:-4] + "abcd"
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(tampered)
    assert exc_info.value.status_code == 401


def test_jwt_rejects_expired_token():
    # expires_minutes отрицательный -> момент истечения уже в прошлом
    token = create_access_token(user_id=42, expires_minutes=-1)
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401


def test_jwt_zero_minute_lifetime_is_expired():
    token = create_access_token(user_id=42, expires_minutes=0)
    time.sleep(0.01)
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401
