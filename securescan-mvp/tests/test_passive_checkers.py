"""Test passive scanners without making real network requests."""
from http.cookiejar import Cookie
from unittest.mock import Mock, patch

from app.scanners.passive.headers_check import HeadersChecker
from app.scanners.passive.cookie_security_check import CookieSecurityChecker
from app.scanners.passive.cors_check import CORSChecker, PROBE_ORIGIN
from app.scanners.passive.exposed_paths_check import ExposedPathsChecker
from app.scanners.passive.http_methods_check import HTTPMethodsChecker
from app.scanners.passive.email_security_check import EmailSecurityChecker
from app.scanners.passive.html_content_check import HTMLContentChecker
from app.scanners.passive.robots_disclosure_check import RobotsDisclosureChecker
from app.scanners.passive.subdomain_takeover_check import SubdomainTakeoverChecker
from app.scanners.passive.tech_fingerprint import TechFingerprintChecker
from app.scanners.passive.outdated_components import OutdatedComponentsChecker
from app.scanners.base import ScanFinding
from app.vulnerability_db.cve_client import (
    common_stack_vuln_matches,
    php_common_vuln_matches,
    php_oom_cve_matches,
)


def make_cookie(name: str, secure: bool = False, httponly: bool = False, samesite: str | None = None) -> Cookie:
    rest = {}
    if httponly:
        rest["HttpOnly"] = None
    if samesite:
        rest["SameSite"] = samesite
    return Cookie(
        0, name, "value", None, False, "example.com", True, False, "/", True,
        secure, None, False, None, None, rest,
    )


# ------------------------------------------------------------ headers_check

def test_headers_check_flags_missing_security_headers():
    resp = Mock(headers={}, url="https://example.com/")
    with patch("requests.get", return_value=resp):
        findings = HeadersChecker().run("example.com")

    titles = [f.title for f in findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_headers_check_passes_when_headers_present():
    resp = Mock(
        headers={
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        },
        url="https://example.com/",
    )
    with patch("requests.get", return_value=resp):
        findings = HeadersChecker().run("example.com")

    assert findings == []


# ------------------------------------------------------------------ cookies

def test_cookie_check_flags_insecure_session_cookie():
    resp = Mock(cookies=[make_cookie("session_id", secure=False, httponly=False, samesite=None)])
    with patch("requests.get", return_value=resp):
        findings = CookieSecurityChecker().run("example.com")

    titles = " ".join(f.title for f in findings)
    assert "Secure" in titles
    assert "HttpOnly" in titles
    assert "SameSite" in titles
    # session_id похоже на сессионную cookie -> повышенная severity
    assert any(f.severity == "medium" for f in findings)


def test_cookie_check_passes_fully_secured_cookie():
    resp = Mock(cookies=[make_cookie("session_id", secure=True, httponly=True, samesite="Lax")])
    with patch("requests.get", return_value=resp):
        findings = CookieSecurityChecker().run("example.com")

    assert all(f.severity == "info" for f in findings)


def test_cookie_check_handles_no_cookies():
    resp = Mock(cookies=[])
    with patch("requests.get", return_value=resp):
        findings = CookieSecurityChecker().run("example.com")

    assert len(findings) == 1
    assert findings[0].severity == "info"


# --------------------------------------------------------------------- cors

def test_cors_check_flags_origin_reflection_with_credentials():
    resp = Mock(headers={
        "Access-Control-Allow-Origin": PROBE_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    })
    with patch("requests.get", return_value=resp):
        findings = CORSChecker().run("example.com")

    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_cors_check_flags_wildcard_as_low():
    resp = Mock(headers={"Access-Control-Allow-Origin": "*"})
    with patch("requests.get", return_value=resp):
        findings = CORSChecker().run("example.com")

    assert findings[0].severity == "low"


def test_cors_check_no_header_is_informational():
    resp = Mock(headers={})
    with patch("requests.get", return_value=resp):
        findings = CORSChecker().run("example.com")

    assert findings[0].severity == "info"


# ------------------------------------------------------------ exposed_paths

def test_exposed_paths_flags_exposed_env_file():
    def fake_get(url, **kwargs):
        if url.endswith("/.env"):
            return Mock(status_code=200, content=b"DB_PASSWORD=secret")
        return Mock(status_code=404, content=b"")

    with patch("requests.get", side_effect=fake_get):
        findings = ExposedPathsChecker().run("example.com")

    exposed = [f for f in findings if ".env" in f.title and "critical" == f.severity]
    assert len(exposed) == 1


def test_exposed_paths_flags_phpinfo_and_admin_installers():
    def fake_get(url, **kwargs):
        if url.endswith("/phpinfo.php"):
            return Mock(status_code=200, content=b"phpinfo")
        if url.endswith("/wp-admin/install.php"):
            return Mock(status_code=200, content=b"WordPress")
        return Mock(status_code=404, content=b"")

    with patch("requests.get", side_effect=fake_get):
        findings = ExposedPathsChecker().run("example.com")

    titles = [f.title for f in findings]
    assert any("phpinfo.php" in t for t in titles)
    assert any("install.php" in t for t in titles)


def test_exposed_paths_clean_site_reports_info_only():
    with patch("requests.get", return_value=Mock(status_code=404, content=b"")):
        findings = ExposedPathsChecker().run("example.com")

    assert all(f.severity == "info" for f in findings)


# --------------------------------------------------------------- http_methods

def test_http_methods_flags_trace():
    resp = Mock(headers={"Allow": "GET, HEAD, OPTIONS, TRACE"})
    with patch("requests.options", return_value=resp):
        findings = HTTPMethodsChecker().run("example.com")

    trace_findings = [f for f in findings if "TRACE" in f.title]
    assert len(trace_findings) == 1
    # TRACE — теоретический вектор (нужен ещё и XSS, и браузеры блокируют
    # сам вектор с середины 2000-х) — см. рубрикатор severity в
    # app/scanners/base.py. Не "high", несмотря на узнаваемое имя.
    assert trace_findings[0].severity == "low"


def test_http_methods_clean_when_only_safe_methods():
    resp = Mock(headers={"Allow": "GET, HEAD, OPTIONS"})
    with patch("requests.options", return_value=resp):
        findings = HTTPMethodsChecker().run("example.com")

    assert all(f.severity == "info" for f in findings)


def test_http_methods_handles_missing_allow_header():
    resp = Mock(headers={})
    with patch("requests.options", return_value=resp):
        findings = HTTPMethodsChecker().run("example.com")

    assert len(findings) == 1
    assert findings[0].severity == "info"


# ----------------------------------------------------------- email_security

def _fake_txt_answer(text: str):
    """Mock one TXT record returned by dns.resolver.resolve."""
    rdata = Mock()
    rdata.strings = [text.encode()]
    return rdata


def test_email_security_flags_missing_spf_and_dmarc():
    import dns.exception

    with patch("dns.resolver.resolve", side_effect=dns.exception.DNSException()):
        findings = EmailSecurityChecker().run("example.com")

    titles = " ".join(f.title for f in findings)
    assert "SPF-запись не найдена" in titles
    assert "DMARC-запись не найдена" in titles


def test_email_security_passes_with_strict_spf_and_dmarc():
    def fake_resolve(name, record_type, lifetime=5.0):
        if name == "example.com" and record_type == "TXT":
            return [_fake_txt_answer("v=spf1 include:_spf.google.com -all")]
        if name == "_dmarc.example.com" and record_type == "TXT":
            return [_fake_txt_answer("v=DMARC1; p=reject; rua=mailto:admin@example.com")]
        if name == "example.com" and record_type == "MX":
            return [Mock(exchange="mx1.example.com.")]
        if name == "example.com" and record_type == "NS":
            return [Mock(target="ns1.example.com."), Mock(target="ns2.example.com.")]
        raise AssertionError(f"unexpected DNS query: {name} {record_type}")

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        findings = EmailSecurityChecker().run("example.com")

    assert all(f.severity == "info" for f in findings)


def test_email_security_flags_permissive_spf():
    import dns.exception

    def fake_resolve(name, record_type, lifetime=5.0):
        if name == "example.com":
            return [_fake_txt_answer("v=spf1 +all")]
        raise dns.exception.DNSException()

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        findings = EmailSecurityChecker().run("example.com")

    spf_findings = [f for f in findings if "+all" in f.title]
    assert len(spf_findings) == 1
    assert spf_findings[0].severity == "high"


def test_email_security_flags_sparse_ns_resilience():
    import dns.exception

    def fake_resolve(name, record_type, lifetime=5.0):
        if name == "example.com" and record_type == "TXT":
            return [_fake_txt_answer("v=spf1 -all")]
        if name == "_dmarc.example.com" and record_type == "TXT":
            return [_fake_txt_answer("v=DMARC1; p=reject")]
        if name == "example.com" and record_type == "NS":
            return [Mock(target="ns1.example.com.")]
        raise dns.exception.DNSException()

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        findings = EmailSecurityChecker().run("example.com")

    ns_findings = [f for f in findings if "NS" in f.title]
    assert len(ns_findings) == 1
    assert ns_findings[0].severity == "low"


def test_email_security_many_mx_records_is_not_flagged():
    """Normal multi-MX configurations must not produce findings."""
    import dns.exception

    def fake_resolve(name, record_type, lifetime=5.0):
        if name == "example.com" and record_type == "TXT":
            return [_fake_txt_answer("v=spf1 -all")]
        if name == "_dmarc.example.com" and record_type == "TXT":
            return [_fake_txt_answer("v=DMARC1; p=reject")]
        if name == "example.com" and record_type == "NS":
            return [Mock(target="ns1.example.com."), Mock(target="ns2.example.com.")]
        raise dns.exception.DNSException()

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        findings = EmailSecurityChecker().run("example.com")

    assert not any("MX" in f.title for f in findings)


# --------------------------------------------------------------- tls_check

def _mock_tls_connection(ssock_mock):
    """Configure the nested TLS context managers to return the socket mock."""
    sock_cm = Mock()
    sock_cm.__enter__ = Mock(return_value=Mock())
    sock_cm.__exit__ = Mock(return_value=False)

    ssock_cm = Mock()
    ssock_cm.__enter__ = Mock(return_value=ssock_mock)
    ssock_cm.__exit__ = Mock(return_value=False)

    return sock_cm, ssock_cm


def test_tls_check_flags_cert_verification_failure():
    from app.scanners.passive.tls_check import TLSChecker
    import ssl as ssl_module

    sock_cm, ssock_cm = _mock_tls_connection(Mock())
    err = ssl_module.SSLCertVerificationError()
    err.verify_message = "self-signed certificate"

    with patch("socket.create_connection", return_value=sock_cm), \
         patch("ssl.SSLContext.wrap_socket", side_effect=err):
        findings = TLSChecker().run("example.com")

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "доверия" in findings[0].title


def test_tls_check_flags_weak_cipher():
    from app.scanners.passive.tls_check import TLSChecker

    ssock = Mock()
    ssock.version.return_value = "TLSv1.3"
    ssock.cipher.return_value = ("RC4-MD5", "TLSv1.0", 40)
    ssock.getpeercert.return_value = {"notAfter": "Jan  1 00:00:00 2099 GMT"}
    sock_cm, ssock_cm = _mock_tls_connection(ssock)

    with patch("socket.create_connection", return_value=sock_cm), \
         patch("ssl.SSLContext.wrap_socket", return_value=ssock_cm):
        findings = TLSChecker().run("example.com")

    weak_cipher_findings = [f for f in findings if "шифр" in f.title.lower()]
    assert len(weak_cipher_findings) == 1
    assert weak_cipher_findings[0].severity == "high"


def test_tls_check_healthy_connection_is_informational():
    from app.scanners.passive.tls_check import TLSChecker

    ssock = Mock()
    ssock.version.return_value = "TLSv1.3"
    ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    ssock.getpeercert.return_value = {"notAfter": "Jan  1 00:00:00 2099 GMT"}
    sock_cm, ssock_cm = _mock_tls_connection(ssock)

    with patch("socket.create_connection", return_value=sock_cm), \
         patch("ssl.SSLContext.wrap_socket", return_value=ssock_cm):
        findings = TLSChecker().run("example.com")

    assert all(f.severity == "info" for f in findings)


# --------------------------------------------------------------- html_content

def test_html_content_flags_mixed_content_script():
    html = '<html><head><script src="http://cdn.example.com/lib.js"></script></head></html>'
    resp = Mock(text=html)
    with patch("requests.get", return_value=resp):
        findings = HTMLContentChecker().run("example.com")

    mixed = [f for f in findings if "Mixed content" in f.title and "script" in f.title]
    assert len(mixed) == 1
    # Активный mixed content блокируется браузерами — low, не high
    assert mixed[0].severity == "low"


def test_html_content_flags_missing_sri():
    html = '<html><head><script src="https://cdn.example.com/lib.js"></script></head></html>'
    resp = Mock(text=html)
    with patch("requests.get", return_value=resp):
        findings = HTMLContentChecker().run("example.com")

    sri = [f for f in findings if "Subresource Integrity" in f.title]
    assert len(sri) == 1
    assert sri[0].severity == "low"


def test_html_content_no_sri_finding_when_integrity_present():
    html = (
        '<html><head><script src="https://cdn.example.com/lib.js" '
        'integrity="sha384-abc123" crossorigin="anonymous"></script></head></html>'
    )
    resp = Mock(text=html)
    with patch("requests.get", return_value=resp):
        findings = HTMLContentChecker().run("example.com")

    assert not any("Subresource Integrity" in f.title for f in findings)


def test_html_content_flags_password_form_over_http():
    html = (
        '<form action="http://example.com/login" method="post">'
        '<input type="text" name="user">'
        '<input type="password" name="pass">'
        '</form>'
    )
    resp = Mock(text=html)
    with patch("requests.get", return_value=resp):
        findings = HTMLContentChecker().run("example.com")

    pwd = [f for f in findings if "пароля" in f.title.lower()]
    assert len(pwd) == 1
    assert pwd[0].severity == "high"


def test_html_content_clean_page_is_informational():
    html = '<html><head><script src="https://cdn.example.com/lib.js" integrity="sha384-x"></script></head></html>'
    resp = Mock(text=html)
    with patch("requests.get", return_value=resp):
        findings = HTMLContentChecker().run("example.com")

    assert all(f.severity == "info" for f in findings)


# --------------------------------------------------------- robots_disclosure

def test_robots_disclosure_flags_sensitive_paths():
    robots_txt = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /public/\n"
    resp = Mock(status_code=200, text=robots_txt)
    with patch("requests.get", return_value=resp):
        findings = RobotsDisclosureChecker().run("example.com")

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "admin" in findings[0].evidence
    assert "backup" in findings[0].evidence
    assert "public" not in findings[0].evidence


def test_robots_disclosure_no_sensitive_paths():
    robots_txt = "User-agent: *\nDisallow: /images/\nDisallow: /assets/\n"
    resp = Mock(status_code=200, text=robots_txt)
    with patch("requests.get", return_value=resp):
        findings = RobotsDisclosureChecker().run("example.com")

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "не раскрывает" in findings[0].title


def test_robots_disclosure_missing_file():
    resp = Mock(status_code=404, text="")
    with patch("requests.get", return_value=resp):
        findings = RobotsDisclosureChecker().run("example.com")

    assert len(findings) == 1
    assert "отсутствует" in findings[0].title


# --------------------------------------------------------- subdomain_takeover

def _fake_cname_answer(target: str):
    """Mock one CNAME record returned by dns.resolver.resolve."""
    rdata = Mock()
    rdata.target = target  # str(target) вызывается в коде — Mock со строковым target подходит
    return rdata


def test_subdomain_takeover_no_cname_is_informational():
    import dns.exception

    with patch("dns.resolver.resolve", side_effect=dns.exception.DNSException()):
        findings = SubdomainTakeoverChecker().run("example.com")

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "CNAME не найден" in findings[0].title


def test_subdomain_takeover_unknown_service_is_informational():
    with patch("dns.resolver.resolve", return_value=[_fake_cname_answer("unknown-host.example.net.")]):
        findings = SubdomainTakeoverChecker().run("sub.example.com")

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "не указывает на известный" in findings[0].title


def test_subdomain_takeover_flags_dangling_cname():
    resp = Mock(text="<html>There isn't a GitHub Pages site here.</html>")
    with patch("dns.resolver.resolve", return_value=[_fake_cname_answer("someuser.github.io.")]), \
         patch("requests.get", return_value=resp):
        findings = SubdomainTakeoverChecker().run("sub.example.com")

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Вероятный subdomain takeover" in findings[0].title
    assert "GitHub Pages" in findings[0].title


def test_subdomain_takeover_claimed_resource_is_informational():
    resp = Mock(text="<html>Welcome to my actual site!</html>")
    with patch("dns.resolver.resolve", return_value=[_fake_cname_answer("someuser.github.io.")]), \
         patch("requests.get", return_value=resp):
        findings = SubdomainTakeoverChecker().run("sub.example.com")

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "похоже занят" in findings[0].title


def test_php_oom_cve_boundaries():
    assert {match.identifier for match in php_oom_cve_matches("8.2.34")} == {
        "CVE-2026-109618",
        "CVE-2026-109619",
    }
    assert {match.identifier for match in php_oom_cve_matches("8.3.35")} == {
        "CVE-2026-109618",
        "CVE-2026-109619",
    }
    assert php_oom_cve_matches("8.2.35") == []
    assert php_oom_cve_matches("8.3.36") == []
    assert [m.identifier for m in php_oom_cve_matches("7.2.34")] == [
        "CVE-2026-109619"
    ]


def test_php_common_advisories_boundaries():
    assert {match.identifier for match in php_common_vuln_matches("8.1.28")} == {
        "CVE-2024-4577",
    }
    assert php_common_vuln_matches("8.1.29") == []
    assert {match.identifier for match in php_common_vuln_matches("8.2.21")} == {
        "CVE-2024-4577",
    }
    assert php_common_vuln_matches("8.2.22") == []
    assert {match.identifier for match in php_common_vuln_matches("8.1.17")} == {
        "CVE-2024-4577",
        "CVE-2023-0567",
    }
    assert {match.identifier for match in php_common_vuln_matches("8.2.16")} == {
        "CVE-2024-4577",
        "CVE-2023-0567",
    }


def test_common_stack_advisories_boundaries():
    assert {match.identifier for match in common_stack_vuln_matches("nginx", "1.24.0")} == {
        "CVE-2023-44487",
    }
    assert common_stack_vuln_matches("nginx", "1.25.1") == []
    assert {match.identifier for match in common_stack_vuln_matches("apache", "2.4.60")} == {
        "CVE-2024-38475",
    }
    assert common_stack_vuln_matches("apache", "2.4.61") == []
    assert {match.identifier for match in common_stack_vuln_matches("openssl", "3.0.11")} == {
        "CVE-2023-3446",
    }
    assert common_stack_vuln_matches("openssl", "3.0.12") == []


def test_outdated_components_reports_php_oom_cves(monkeypatch):
    monkeypatch.setattr(
        TechFingerprintChecker,
        "run",
        lambda self, domain: [
            ScanFinding(
                checker="tech_fingerprint",
                title="Detected PHP",
                severity="info",
                description="PHP version exposed by response headers.",
                evidence="PHP=8.2.34",
            )
        ],
    )
    monkeypatch.setattr(
        "app.scanners.passive.outdated_components.query_nvd",
        lambda product, version: [],
    )

    findings = OutdatedComponentsChecker().run("example.com")

    assert {finding.evidence for finding in findings if finding.evidence} == {
        "CVE-2026-109618",
        "CVE-2026-109619",
    }


def test_php_fingerprint_detects_version_in_server_header():
    response = Mock(text="", headers={"Server": "Apache PHP/8.4.26"})
    with patch("requests.get", return_value=response):
        findings = TechFingerprintChecker().run("example.com")

    assert any(f.evidence == "PHP=8.4.26" for f in findings)
