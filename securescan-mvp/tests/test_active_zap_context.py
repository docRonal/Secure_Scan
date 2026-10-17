from app.scanners.active.zap_scanner import ZAPActiveScanner


def test_contextual_findings_enrich_alerts():
    alerts = [
        {"alert": "SQL Injection", "risk": "High", "url": "https://example.com/login"},
        {"alert": "Open Redirect", "risk": "Medium", "url": "https://example.com/redirect"},
    ]

    findings = ZAPActiveScanner._add_contextual_findings("https://example.com/", alerts)

    titles = [f.title for f in findings]
    assert any("инъекций" in t.lower() for t in titles)
    assert any("open redirect" in t.lower() for t in titles)
