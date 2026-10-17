"""Check a small fixed list of commonly exposed sensitive files and paths."""
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# (path, severity, description)
SENSITIVE_PATHS = [
    (".git/config", "high", "Раскрыт .git/config — можно восстановить историю репозитория и, возможно, секреты в ней"),
    (".env", "critical", "Раскрыт файл .env — как правило содержит пароли БД, API-ключи и другие секреты"),
    (".env.example", "info", ".env.example обычно не секретен, но может подсказать структуру реальных секретов"),
    ("wp-config.php.bak", "critical", "Раскрыт бэкап конфигурации WordPress с учётными данными БД"),
    ("config.php.bak", "critical", "Раскрыт бэкап файла конфигурации"),
    ("phpinfo.php", "high", "Раскрыт phpinfo.php — позволяет получить структуру окружения, версии PHP и конфигурацию сервера"),
    ("wp-admin/install.php", "high", "Раскрыт установочный сценарий WordPress — может позволить переустановить/достроить сайт"),
    (".DS_Store", "low", "Раскрыт служебный файл macOS Finder — может содержать список файлов в директории"),
    ("backup.zip", "high", "Раскрыт архив backup.zip в корне сайта"),
    ("docker-compose.yml", "medium", "Раскрыт docker-compose.yml — может содержать имена сервисов, порты, иногда пароли"),
    (".well-known/security.txt", "info", "security.txt найден — это хорошо: сайт публикует контакты для ответственного раскрытия уязвимостей"),
]

# Paths where HTTP 200 is expected and does not indicate disclosure.
POSITIVE_PATHS = {".well-known/security.txt"}


class ExposedPathsChecker(BaseScanner):
    name = "exposed_paths_check"

    def run(self, domain: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        headers = {"User-Agent": settings.http_user_agent}

        for path, severity, description in SENSITIVE_PATHS:
            url = f"https://{domain}/{path}"
            try:
                resp = requests.get(
                    url, headers=headers, timeout=settings.http_timeout_seconds, allow_redirects=False
                )
            except requests.RequestException:
                continue

            found = resp.status_code == 200 and len(resp.content) > 0

            if path in POSITIVE_PATHS:
                if found:
                    findings.append(
                        ScanFinding(
                            checker=self.name,
                            title=f"{path} присутствует",
                            severity="info",
                            description=description,
                        )
                    )
                continue

            if found:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Раскрыт чувствительный путь: /{path}",
                        severity=severity,
                        description=description,
                        recommendation=f"Удалите /{path} с продакшн-сервера или закройте к нему доступ на уровне веб-сервера.",
                        owasp_category="A05:2021",
                        cwe_id="CWE-538",
                        evidence=f"GET /{path} -> HTTP {resp.status_code}, {len(resp.content)} bytes",
                    )
                )

        if not any(f.severity != "info" for f in findings):
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Явно раскрытых чувствительных файлов не найдено",
                    severity="info",
                    description=f"Проверено {len(SENSITIVE_PATHS)} типовых путей — ничего критичного не обнаружено.",
                )
            )

        return findings
