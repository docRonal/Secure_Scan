"""Inspect homepage HTML for mixed content, missing SRI, and insecure forms."""
import re
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# Modern browsers block active mixed content; passive mixed content is only informational.
ACTIVE_MIXED_CONTENT_TAGS = {
    "script": ("src", "low"),
    "link": ("href", "low"),
    "iframe": ("src", "low"),
}
PASSIVE_MIXED_CONTENT_TAGS = {
    "img": ("src", "info"),
    "audio": ("src", "info"),
    "video": ("src", "info"),
}

SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\'](https?://[^"\']+)["\'][^>]*>', re.IGNORECASE)
INTEGRITY_PATTERN = re.compile(r'integrity=["\']', re.IGNORECASE)
FORM_PATTERN = re.compile(r'<form[^>]*action=["\'](http://[^"\']*)["\'][^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
PASSWORD_INPUT_PATTERN = re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE)


class HTMLContentChecker(BaseScanner):
    name = "html_content_check"

    def run(self, domain: str) -> list[ScanFinding]:
        url = f"https://{domain}/"
        headers = {"User-Agent": settings.http_user_agent}
        try:
            resp = requests.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        except requests.RequestException as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось получить главную страницу для анализа HTML",
                    severity="info",
                    description=str(exc),
                )
            ]

        html = resp.text
        findings: list[ScanFinding] = []
        findings += self._check_mixed_content(html)
        findings += self._check_missing_sri(html)
        findings += self._check_password_over_http(html)

        if not findings:
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Явных проблем в содержимом главной страницы не найдено",
                    severity="info",
                    description="Mixed content, отсутствие SRI и формы с паролем по HTTP не обнаружены.",
                )
            )
        return findings

    def _check_mixed_content(self, html: str) -> list[ScanFinding]:
        findings = []
        for tag, (attr, severity) in {**ACTIVE_MIXED_CONTENT_TAGS, **PASSIVE_MIXED_CONTENT_TAGS}.items():
            pattern = re.compile(rf'<{tag}[^>]+{attr}=["\']http://[^"\']+["\']', re.IGNORECASE)
            matches = pattern.findall(html)
            if matches:
                is_active = tag in ACTIVE_MIXED_CONTENT_TAGS
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Mixed content: <{tag}> загружается по HTTP на HTTPS-странице",
                        severity=severity,
                        description=(
                            f"Найдено {len(matches)} тег(ов) <{tag}> с {attr} по HTTP."
                            + (
                                " Современные браузеры блокируют такую загрузку автоматически "
                                "(это \"активный\" mixed content), но лучше исправить в разметке."
                                if is_active
                                else " Браузер загрузит ресурс, но покажет предупреждение о смешанном контенте."
                            )
                        ),
                        recommendation=f"Замените http:// на https:// (или протокол-независимый //) для <{tag}>.",
                        owasp_category="A02:2021",
                        cwe_id="CWE-319",
                    )
                )
        return findings

    def _check_missing_sri(self, html: str) -> list[ScanFinding]:
        scripts = SCRIPT_SRC_PATTERN.findall(html)
        if not scripts:
            return []
        # Check the full script element for an integrity attribute.
        script_tags = re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', html, re.IGNORECASE)
        missing = [tag for tag in script_tags if not INTEGRITY_PATTERN.search(tag)]
        if not missing:
            return []
        return [
            ScanFinding(
                checker=self.name,
                title=f"Внешние скрипты без Subresource Integrity (SRI): {len(missing)} шт.",
                severity="low",
                description=(
                    "Скрипты загружаются с внешних доменов без атрибута integrity. "
                    "Реально эксплуатируется только при компрометации самого CDN "
                    "(отдельное, внешнее условие) — поэтому low, а не high."
                ),
                recommendation="Добавьте атрибут integrity (SHA-384 хэш) и crossorigin=\"anonymous\" к внешним <script>.",
                owasp_category="A08:2021",
                cwe_id="CWE-829",
                evidence=missing[0][:200],
            )
        ]

    def _check_password_over_http(self, html: str) -> list[ScanFinding]:
        findings = []
        for match in FORM_PATTERN.finditer(html):
            action_url, form_body = match.group(1), match.group(2)
            if PASSWORD_INPUT_PATTERN.search(form_body):
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title="Форма с полем пароля отправляет данные по HTTP",
                        severity="high",
                        description=(
                            f"Форма с action=\"{action_url}\" содержит поле type=\"password\", "
                            "но отправляет данные по незашифрованному HTTP."
                        ),
                        recommendation="Поменяйте action формы на https:// — иначе пароль передаётся в открытом виде.",
                        owasp_category="A02:2021",
                        cwe_id="CWE-319",
                        evidence=f'<form action="{action_url}">',
                    )
                )
        return findings
