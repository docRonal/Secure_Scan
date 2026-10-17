"""Identify technologies from public response headers, HTML, and cookies."""
import re
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# Demo signatures only; production deployments should use an updatable technology database.
SIGNATURES = [
    {
        "name": "WordPress",
        "pattern": re.compile(r'<meta name="generator" content="WordPress ([\d.]+)"', re.I),
        "source": "body",
    },
    {
        "name": "Drupal",
        "pattern": re.compile(r'Drupal ([\d.]+)', re.I),
        "source": "body",
    },
    {
        "name": "PHP",
        "pattern": re.compile(r'PHP/([\d.]+)', re.I),
        "source": "header:X-Powered-By",
    },
    {
        "name": "nginx",
        "pattern": re.compile(r'nginx/([\d.]+)', re.I),
        "source": "header:Server",
    },
    {
        "name": "Apache",
        "pattern": re.compile(r'Apache/([\d.]+)', re.I),
        "source": "header:Server",
    },
]


class TechFingerprintChecker(BaseScanner):
    name = "tech_fingerprint"

    def run(self, domain: str) -> list[ScanFinding]:
        url = f"https://{domain}/"
        headers = {"User-Agent": settings.http_user_agent}
        try:
            resp = requests.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        except requests.RequestException as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось получить главную страницу для fingerprinting",
                    severity="info",
                    description=str(exc),
                )
            ]

        detected: list[ScanFinding] = []
        for sig in SIGNATURES:
            haystack = (
                resp.text if sig["source"] == "body" else resp.headers.get(sig["source"].split(":")[1], "")
            )
            match = sig["pattern"].search(haystack or "")
            if match:
                version = match.group(1) if match.groups() else "unknown"
                detected.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Обнаружена технология: {sig['name']} {version}",
                        severity="info",
                        description=(
                            f"На основе публичного ответа сервера обнаружено использование "
                            f"{sig['name']} версии {version}."
                        ),
                        evidence=f"{sig['name']}={version}",
                    )
                )

        if not detected:
            detected.append(
                ScanFinding(
                    checker=self.name,
                    title="Явных сигнатур технологий не обнаружено",
                    severity="info",
                    description="Ни одна из известных сигнатур не совпала с ответом сервера.",
                )
            )

        return detected
