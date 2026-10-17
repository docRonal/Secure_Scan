from app.config import settings
from app.scanners.active.zap_client import ZAPClient
from app.scanners.active.zap_scanner import ZAPActiveScanner


def test_default_zap_policy_is_untouched_by_default():
    assert settings.zap_scan_policy is None
    assert settings.zap_attack_strength == "High"
    assert settings.zap_alert_threshold == "Low"
    assert settings.zap_enable_all_scanners is True


def test_configure_scan_policy_falls_back_when_attack_strength_is_unsupported():
    calls = []
    client = ZAPClient("http://127.0.0.1:8080", "secret")

    def fake_get(path, params=None):
        calls.append((path, params))
        if path == "/JSON/ascan/view/scanners/":
            return {"scanners": [{"id": "40018"}]}
        return {}

    client._get = fake_get

    client.configure_scan_policy(
        "My Custom Policy",
        attack_strength="Insane",
        alert_threshold="Low",
        enable_all_scanners=True,
    )

    assert calls[1][1]["attackStrength"] == "High"


def test_ajax_spider_uses_zap_api():
    calls = []
    client = ZAPClient("http://127.0.0.1:8080", "secret")

    def fake_get(path, params=None):
        calls.append((path, params))
        if path == "/JSON/ajaxSpider/view/status/":
            return {"status": "stopped"}
        return {}

    client._get = fake_get

    client.start_ajax_spider("https://example.com/")
    assert client.ajax_spider_status() == 100

    assert calls[0] == (
        "/JSON/ajaxSpider/action/scan/",
        {"url": "https://example.com/", "inScope": "true"},
    )
    assert calls[1][0] == "/JSON/ajaxSpider/view/status/"


def test_configure_scan_policy_applies_stronger_settings():
    calls = []
    client = ZAPClient("http://127.0.0.1:8080", "secret")

    def fake_get(path, params=None):
        calls.append((path, params))
        if path == "/JSON/ascan/view/scanners/":
            return {"scanners": [{"id": "40018"}]}
        return {}

    client._get = fake_get

    client.configure_scan_policy(
        "My Custom Policy",
        attack_strength="High",
        alert_threshold="Medium",
        enable_all_scanners=True,
    )

    assert calls[1][0] == "/JSON/ascan/action/setScannerAttackStrength/"
    assert calls[1][1]["attackStrength"] == "High"
    assert calls[2][0] == "/JSON/ascan/action/setScannerAlertThreshold/"
    assert calls[2][1]["alertThreshold"] == "Medium"
    assert calls[3][0] == "/JSON/ascan/action/enableAllScanners/"


def test_zap_finding_includes_confidence_and_instance_evidence():
    finding = ZAPActiveScanner._to_finding(
        {
            "alert": "Reflected Cross Site Scripting",
            "risk": "High",
            "confidence": "High",
            "description": "Input is reflected unsafely.",
            "instances": [
                {
                    "uri": "https://example.com/search",
                    "method": "GET",
                    "param": "q",
                    "attack": "<test-marker>",
                    "evidence": "<test-marker>",
                }
            ],
        }
    )

    assert "Confidence: High" in finding.description
    assert "GET https://example.com/search" in finding.evidence
    assert "param=q" in finding.evidence
    assert "evidence=<test-marker>" in finding.evidence
