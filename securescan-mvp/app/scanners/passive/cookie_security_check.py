"""Inspect security attributes on cookies returned by a standard GET request."""
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# Session and authentication cookies need stricter flag checks.
SENSITIVE_NAME_HINTS = ("session", "sess", "auth", "token", "jwt", "sid", "login")


class CookieSecurityChecker(BaseScanner):
    name = "cookie_security_check"

    def run(self, domain: str) -> list[ScanFinding]:
        url = f"https://{domain}/"
        headers = {"User-Agent": settings.http_user_agent}
        try:
            resp = requests.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        except requests.RequestException as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось получить cookies для проверки",
                    severity="info",
                    description=str(exc),
                )
            ]

        cookies = list(resp.cookies)
        if not cookies:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Сайт не устанавливает cookies на главной странице",
                    severity="info",
                    description="Set-Cookie отсутствует в ответе — проверка неприменима на этой странице.",
                )
            ]

        findings: list[ScanFinding] = []
        for cookie in cookies:
            name = cookie.name
            is_sensitive = any(hint in name.lower() for hint in SENSITIVE_NAME_HINTS)
            base_severity = "medium" if is_sensitive else "low"
            evidence = (
                f"{name}: secure={cookie.secure}, "
                f"httponly={cookie.has_nonstandard_attr('HttpOnly')}, "
                f"samesite={cookie.get_nonstandard_attr('SameSite', 'не указан')}"
            )

            if not cookie.secure:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Cookie '{name}' установлена без флага Secure",
                        severity=base_severity,
                        description=f"Cookie '{name}' может быть передана по незашифрованному HTTP-соединению.",
                        recommendation="Добавьте флаг Secure, чтобы cookie передавалась только по HTTPS.",
                        owasp_category="A05:2021",
                        cwe_id="CWE-614",
                        evidence=evidence,
                    )
                )
            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Cookie '{name}' установлена без флага HttpOnly",
                        severity=base_severity,
                        description=f"Cookie '{name}' доступна из JavaScript — при наличии XSS её можно похитить.",
                        recommendation="Добавьте флаг HttpOnly для cookie, не используемых напрямую в JS.",
                        owasp_category="A05:2021",
                        cwe_id="CWE-1004",
                        evidence=evidence,
                    )
                )
            if not cookie.has_nonstandard_attr("SameSite"):
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Cookie '{name}' установлена без атрибута SameSite",
                        severity="medium" if is_sensitive else "low",
                        description=f"Cookie '{name}' не ограничивает межсайтовую отправку — повышает риск CSRF и межсайтового использования сессии.",
                        recommendation="Добавьте SameSite=Lax (или Strict, если это не мешает интеграциям).",
                        owasp_category="A01:2021",
                        cwe_id="CWE-352",
                        evidence=evidence,
                    )
                )

        if not findings:
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Флаги безопасности cookies в порядке",
                    severity="info",
                    description="Обнаруженные cookies установлены с Secure, HttpOnly и SameSite.",
                )
            )

        return findings
