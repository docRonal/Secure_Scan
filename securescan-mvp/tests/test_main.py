"""Tests for application-level error handling."""
import asyncio

from fastapi import Request

from app.main import _validate_active_scanning_config, unhandled_exception_handler


def test_unhandled_exception_response_does_not_expose_exception_details():
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("127.0.0.1", 1234),
        "scheme": "http",
    })
    response = asyncio.run(
        unhandled_exception_handler(request, RuntimeError("database password leaked"))
    )

    assert response.status_code == 500
    assert response.body == b'{"detail":"Internal server error"}'


def test_missing_zap_key_is_allowed_when_active_scanning_is_disabled(monkeypatch):
    monkeypatch.setattr("app.main.settings.zap_enabled", False)
    monkeypatch.setattr("app.main.settings.zap_api_key", None)

    _validate_active_scanning_config()


def test_missing_zap_key_is_rejected_when_active_scanning_is_enabled(monkeypatch):
    monkeypatch.setattr("app.main.settings.zap_enabled", True)
    monkeypatch.setattr("app.main.settings.zap_api_key", None)

    try:
        _validate_active_scanning_config()
    except RuntimeError as exc:
        assert str(exc) == "ZAP_API_KEY must be set when ZAP_ENABLED=true"
    else:
        raise AssertionError("Missing ZAP_API_KEY should prevent active scanning startup")