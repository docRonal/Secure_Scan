"""Identify potentially sensitive paths disclosed by a public robots.txt file."""
import re
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

SENSITIVE_KEYWORDS = (
    "admin", "administrator", "backup", "config", "private", "internal",
    "staging", "test", "dev", "debug", "secret", "credential", "database",
    "db", "dump", "api-docs", "swagger", "phpmyadmin", "wp-admin", ".git",
    "console", "manage", "panel", "old", "tmp", "temp",
)

DISALLOW_PATTERN = re.compile(r'^\s*Disallow:\s*(\S+)', re.IGNORECASE | re.MULTILINE)


class RobotsDisclosureChecker(BaseScanner):
    name = "robots_disclosure_check"

    def run(self, domain: str) -> list[ScanFinding]:
        url = f"https://{domain}/robots.txt"
        headers = {"User-Agent": settings.http_user_agent}
        try:
            resp = requests.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        except requests.RequestException as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось получить robots.txt",
                    severity="info",
                    description=str(exc),
                )
            ]

        if resp.status_code != 200 or not resp.text.strip():
            return [
                ScanFinding(
                    checker=self.name,
                    title="robots.txt отсутствует",
                    severity="info",
                    description="Файл robots.txt не найден — анализировать нечего.",
                )
            ]

        disallowed = DISALLOW_PATTERN.findall(resp.text)
        interesting = [
            path for path in disallowed
            if path not in ("/", "") and any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)
        ]

        if not interesting:
            return [
                ScanFinding(
                    checker=self.name,
                    title="robots.txt не раскрывает путей, похожих на чувствительные",
                    severity="info",
                    description=f"Всего Disallow-записей: {len(disallowed)}, ни одна не выглядит чувствительной.",
                )
            ]

        return [
            ScanFinding(
                checker=self.name,
                title=f"robots.txt раскрывает потенциально чувствительные пути: {len(interesting)} шт.",
                severity="info",
                description=(
                    "robots.txt просит поисковые системы не индексировать эти пути — но сам файл "
                    "публично читаем, так что список фактически виден любому. Это не уязвимость "
                    "сама по себе (доступность путей отдельный вопрос), а разведочная информация."
                ),
                recommendation=(
                    "Не полагайтесь на robots.txt как на контроль доступа — закрывайте "
                    "чувствительные пути аутентификацией, а не просьбой к роботам их не индексировать."
                ),
                owasp_category="A05:2021",
                cwe_id="CWE-200",
                evidence=", ".join(interesting[:10]),
            )
        ]
