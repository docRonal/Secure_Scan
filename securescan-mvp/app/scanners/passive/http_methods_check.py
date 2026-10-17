"""Inspect the Allow response header using a standard OPTIONS request."""
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# TRACE is rated low: current browsers block the historical XST vector, and
# exploitation would also require a separate XSS vulnerability.
DANGEROUS_METHODS = {
    "TRACE": ("low", "CWE-693", "Теоретический вектор Cross-Site Tracing (XST) — требует ещё и отдельный XSS, а современные браузеры (с середины 2000-х) блокируют его на уровне движка. Низкий практический риск, но стоит отключить по гигиене конфигурации."),
    "TRACK": ("low", "CWE-693", "Аналог TRACE в некоторых реализациях (например IIS) — тот же теоретический и уже во многом устаревший риск XST, см. TRACE."),
    "PUT": ("medium", "CWE-650", "Если доступен без аутентификации — потенциально позволяет загружать произвольные файлы на сервер."),
    "DELETE": ("medium", "CWE-650", "Если доступен без аутентификации — потенциально позволяет удалять ресурсы на сервере."),
}


class HTTPMethodsChecker(BaseScanner):
    name = "http_methods_check"

    def run(self, domain: str) -> list[ScanFinding]:
        url = f"https://{domain}/"
        headers = {"User-Agent": settings.http_user_agent}
        try:
            resp = requests.options(url, headers=headers, timeout=settings.http_timeout_seconds)
        except requests.RequestException as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось выполнить OPTIONS-запрос",
                    severity="info",
                    description=str(exc),
                )
            ]

        allow_header = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        if not allow_header:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Сервер не сообщает список разрешённых методов",
                    severity="info",
                    description="Заголовок Allow/Access-Control-Allow-Methods отсутствует в ответе на OPTIONS.",
                )
            ]

        allowed = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
        findings: list[ScanFinding] = []

        for method, (severity, cwe, description) in DANGEROUS_METHODS.items():
            if method in allowed:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"HTTP-метод {method} разрешён",
                        severity=severity,
                        description=description,
                        recommendation=f"Отключите метод {method} на уровне веб-сервера, если он не используется намеренно.",
                        owasp_category="A05:2021",
                        cwe_id=cwe,
                        evidence=f"Allow: {allow_header}",
                    )
                )

        if not findings:
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Опасных HTTP-методов не обнаружено",
                    severity="info",
                    description=f"Разрешённые методы: {allow_header}",
                )
            )

        return findings
