"""Inspect HTTP security headers using a standard GET request."""
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# (header, whether it is required, recommendation when missing)
EXPECTED_HEADERS = [
    (
        "Strict-Transport-Security",
        "medium",
        "Добавьте заголовок Strict-Transport-Security (HSTS), чтобы браузеры "
        "всегда обращались к сайту по HTTPS и не были уязвимы к SSL-stripping.",
    ),
    (
        "Content-Security-Policy",
        "medium",
        "Добавьте Content-Security-Policy, чтобы ограничить источники "
        "загружаемых скриптов/стилей и снизить риск XSS.",
    ),
    (
        "X-Content-Type-Options",
        "low",
        "Добавьте заголовок 'X-Content-Type-Options: nosniff', чтобы браузер "
        "не переопределял MIME-тип ответа.",
    ),
    (
        "X-Frame-Options",
        "low",
        "Добавьте 'X-Frame-Options: DENY' или используйте frame-ancestors в CSP, "
        "чтобы защититься от clickjacking.",
    ),
    (
        "Referrer-Policy",
        "info",
        "Добавьте Referrer-Policy, чтобы контролировать объём данных, "
        "передаваемых в заголовке Referer при переходах с сайта.",
    ),
]

# Headers that disclose software versions and aid reconnaissance.
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HeadersChecker(BaseScanner):
    name = "headers_check"

    def run(self, domain: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        url = f"https://{domain}/"
        headers = {"User-Agent": settings.http_user_agent}

        try:
            resp = requests.get(
                url, headers=headers, timeout=settings.http_timeout_seconds, allow_redirects=True
            )
        except requests.RequestException as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось подключиться к сайту по HTTPS",
                    severity="info",
                    description=f"Запрос к {url} завершился ошибкой: {exc}",
                )
            ]

        resp_headers = resp.headers

        for header_name, severity, recommendation in EXPECTED_HEADERS:
            if header_name not in resp_headers:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Отсутствует заголовок {header_name}",
                        severity=severity,
                        description=(
                            f"Ответ сервера не содержит заголовок '{header_name}'."
                        ),
                        recommendation=recommendation,
                        owasp_category="A05:2021",
                        cwe_id="CWE-693",
                    )
                )

        for header_name in INFO_LEAK_HEADERS:
            if header_name in resp_headers:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Заголовок {header_name} раскрывает версию ПО",
                        severity="low",
                        description=(
                            f"Заголовок '{header_name}: {resp_headers[header_name]}' "
                            "раскрывает технологию и/или её версию, что упрощает "
                            "разведку для потенциального атакующего."
                        ),
                        recommendation=f"Скройте или обезличьте заголовок {header_name} на уровне веб-сервера.",
                        owasp_category="A05:2021",
                        cwe_id="CWE-200",
                        evidence=f"{header_name}: {resp_headers[header_name]}",
                    )
                )

        if not resp.url.startswith("https://"):
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Сайт не редиректит на HTTPS",
                    severity="high",
                    description="Финальный URL после редиректов не использует HTTPS.",
                    recommendation="Настройте принудительный редирект с HTTP на HTTPS на уровне веб-сервера/балансировщика.",
                    owasp_category="A02:2021",
                    cwe_id="CWE-319",
                )
            )

        if resp.headers.get("Location", "").startswith("http://"):
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Сервер выполняет insecure redirect на HTTP",
                    severity="low",
                    description="Ответ отдаёт Location с http://, что может приводить к утечке токенов/сессий через downgrade attack.",
                    recommendation="Используйте только HTTPS-redirects и не передавайте чувствительные параметры на HTTP.",
                    owasp_category="A02:2021",
                    cwe_id="CWE-319",
                    evidence=resp.headers.get("Location"),
                )
            )

        return findings
