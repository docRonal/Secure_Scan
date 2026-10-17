"""Inspect CORS response headers using a standard cross-origin request."""
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# A reflected untrusted origin indicates an unsafe CORS allow-list.
PROBE_ORIGIN = "https://securescan-ai-cors-probe.example"


class CORSChecker(BaseScanner):
    name = "cors_check"

    def run(self, domain: str) -> list[ScanFinding]:
        url = f"https://{domain}/"
        headers = {"User-Agent": settings.http_user_agent, "Origin": PROBE_ORIGIN}
        try:
            resp = requests.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        except requests.RequestException as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось проверить CORS-заголовки",
                    severity="info",
                    description=str(exc),
                )
            ]

        allow_origin = resp.headers.get("Access-Control-Allow-Origin")
        allow_credentials = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if not allow_origin:
            return [
                ScanFinding(
                    checker=self.name,
                    title="CORS не настроен на главной странице",
                    severity="info",
                    description=(
                        "Access-Control-Allow-Origin отсутствует — cross-origin чтение ответа браузером "
                        "заблокировано по умолчанию (это нормально и безопасно для большинства сайтов)."
                    ),
                )
            ]

        if allow_origin == PROBE_ORIGIN:
            severity = "critical" if allow_credentials else "high"
            return [
                ScanFinding(
                    checker=self.name,
                    title="CORS отражает произвольный Origin (reflection)",
                    severity=severity,
                    description=(
                        "Сервер вернул Access-Control-Allow-Origin, в точности совпадающий с "
                        "переданным Origin, а не фиксированный whitelist — значит, ЛЮБОЙ сторонний "
                        "сайт может выполнить cross-origin запрос и прочитать ответ от имени "
                        "посетителя." + (" Дополнительно выставлен Access-Control-Allow-Credentials: "
                        "true — это означает, что такой запрос выполнится с cookies пользователя, "
                        "то есть от его имени в залогиненной сессии." if allow_credentials else "")
                    ),
                    recommendation=(
                        "Замените отражение Origin на явный whitelist разрешённых доменов на "
                        "стороне сервера. Если Allow-Credentials не нужен — уберите его."
                    ),
                    owasp_category="A01:2021",
                    cwe_id="CWE-942",
                    evidence=f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {allow_origin}"
                    + (", Access-Control-Allow-Credentials: true" if allow_credentials else ""),
                )
            ]

        if allow_origin == "*":
            findings = [
                ScanFinding(
                    checker=self.name,
                    title="CORS открыт для всех источников (Access-Control-Allow-Origin: *)",
                    severity="low",
                    description=(
                        "Ответ доступен для чтения с любого сайта. Приемлемо для полностью "
                        "публичных данных, но если в ответе есть cookies, authorization headers или "
                        "персональные данные — это уже реальный риск кросс-сайтового доступа."
                    ),
                    recommendation=(
                        "Убедитесь, что на эндпоинтах с '*' не отдаются персональные/сессионные данные."
                    ),
                    owasp_category="A01:2021",
                    cwe_id="CWE-942",
                    evidence=f"Access-Control-Allow-Origin: *",
                )
            ]
            return findings

        return [
            ScanFinding(
                checker=self.name,
                title="CORS настроен с конкретным разрешённым источником",
                severity="info",
                description=f"Access-Control-Allow-Origin указывает на фиксированный домен: {allow_origin}.",
            )
        ]
