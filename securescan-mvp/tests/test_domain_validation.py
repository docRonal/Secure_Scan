"""Tests for domain normalization and validation."""
import pytest
from pydantic import ValidationError

from app.models import AssetCreate


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com", "example.com"),
        ("https://example.com/some/page", "example.com"),
        ("http://github.com/docRonal", "github.com"),
        ("example.com:8080", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("https://mvs.gov.ua/vsanuigeroya/mvs-policeiski", "mvs.gov.ua"),
        ("sub.example.co.uk", "sub.example.co.uk"),
        ("EXAMPLE.COM/", "example.com"),
    ],
)
def test_domain_normalization(raw, expected):
    asset = AssetCreate(domain=raw)
    assert asset.domain == expected


@pytest.mark.parametrize(
    "raw",
    ["not a domain", "localhost", "", "   ", "-example.com", "example-.com", "192.168.1.1"],
)
def test_rejects_invalid_domains(raw):
    with pytest.raises(ValidationError):
        AssetCreate(domain=raw)
