from types import SimpleNamespace

import dns.exception
import dns.resolver

from app.verification.dns_verify import check_dns_txt


def test_dns_verification_accepts_matching_txt_token(monkeypatch):
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        lambda name, record_type, lifetime: [SimpleNamespace(strings=[b"verify=token"])],
    )

    assert check_dns_txt("example.com", "verify=token") is True


def test_dns_verification_rejects_nonmatching_txt_token(monkeypatch):
    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        lambda name, record_type, lifetime: [SimpleNamespace(strings=[b"other=token"])],
    )

    assert check_dns_txt("example.com", "verify=token") is False


def test_dns_verification_rejects_missing_txt_record(monkeypatch):
    monkeypatch.setattr(dns.resolver, "resolve", lambda *args, **kwargs: [])

    assert check_dns_txt("example.com", "verify=token") is False


def test_dns_verification_rejects_dns_errors(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise dns.exception.Timeout

    monkeypatch.setattr(dns.resolver, "resolve", raise_timeout)

    assert check_dns_txt("example.com", "verify=token") is False