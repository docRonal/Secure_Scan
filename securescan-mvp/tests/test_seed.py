"""Tests for explicit account and demo-data seeding controls."""
import pytest

from app import seed
from app.config import settings


def test_demo_data_seeding_requires_its_own_opt_in(monkeypatch):
    monkeypatch.setattr(settings, "seed_admin_enabled", True)
    monkeypatch.setattr(settings, "seed_admin_password", "test-only-password")
    monkeypatch.setattr(settings, "seed_demo_data_enabled", False)
    monkeypatch.setattr(seed, "SessionLocal", lambda: pytest.fail("Database should not be opened"))

    seed.seed_demo_data()