"""Detect dangling CNAME records that may allow subdomain takeover."""
import dns.resolver
import dns.exception
import requests

from app.config import settings
from app.scanners.base import BaseScanner, ScanFinding

# (CNAME substring, unclaimed-resource response text, service name)
# This is a limited signature set; consult can-i-take-over-xyz for broader coverage.
TAKEOVER_SIGNATURES = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("s3-website", "NoSuchBucket", "AWS S3 (website hosting)"),
    ("azurewebsites.net", "Web Site not found", "Azure App Service"),
    ("shopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("wordpress.com", "Do you want to register", "WordPress.com"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("bitbucket.io", "Repository not found", "Bitbucket Pages"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("unbouncepages.com", "The requested URL was not found on this server", "Unbounce"),
]


class SubdomainTakeoverChecker(BaseScanner):
    name = "subdomain_takeover_check"

    def run(self, domain: str) -> list[ScanFinding]:
        try:
            answers = dns.resolver.resolve(domain, "CNAME", lifetime=5.0)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return [
                ScanFinding(
                    checker=self.name,
                    title="CNAME не найден — проверка неприменима",
                    severity="info",
                    description="У домена нет CNAME-записи (обычный A-record) — риск такого класса не относится к этому активу.",
                )
            ]

        cname_target = str(answers[0].target).rstrip(".").lower()

        matched_service = None
        expected_signature = None
        for pattern, signature, service_name in TAKEOVER_SIGNATURES:
            if pattern in cname_target:
                matched_service = service_name
                expected_signature = signature
                break

        if matched_service is None:
            return [
                ScanFinding(
                    checker=self.name,
                    title="CNAME не указывает на известный облачный сервис",
                    severity="info",
                    description=f"CNAME указывает на {cname_target} — сервис не входит в наш список известных паттернов takeover, риск не проверялся.",
                )
            ]

        headers = {"User-Agent": settings.http_user_agent}
        try:
            resp = requests.get(
                f"https://{domain}/", headers=headers, timeout=settings.http_timeout_seconds
            )
            body = resp.text
        except requests.RequestException:
            try:
                resp = requests.get(
                    f"http://{domain}/", headers=headers, timeout=settings.http_timeout_seconds
                )
                body = resp.text
            except requests.RequestException as exc:
                return [
                    ScanFinding(
                        checker=self.name,
                        title=f"CNAME указывает на {matched_service}, но сайт недоступен для проверки",
                        severity="medium",
                        description=(
                            f"CNAME → {cname_target} ({matched_service}), но не удалось получить "
                            f"содержимое для проверки на признаки незанятого ресурса: {exc}. "
                            "Недоступность сама по себе — тоже сигнал возможного dangling CNAME."
                        ),
                        recommendation=f"Проверьте вручную, занят ли ресурс на {matched_service}, или удалите неиспользуемую CNAME-запись.",
                        owasp_category="A05:2021",
                        cwe_id="CWE-350",
                        evidence=f"CNAME: {cname_target}",
                    )
                ]

        if expected_signature.lower() in body.lower():
            return [
                ScanFinding(
                    checker=self.name,
                    title=f"Вероятный subdomain takeover: {matched_service}",
                    severity="high",
                    description=(
                        f"CNAME домена указывает на {cname_target} ({matched_service}), а ответ "
                        f"содержит признак незанятого ресурса ('{expected_signature}'). Кто угодно "
                        f"потенциально может зарегистрировать этот ресурс на {matched_service} под "
                        "своим аккаунтом и получить контроль над контентом, который откроется по "
                        "вашему поддомену."
                    ),
                    recommendation=(
                        f"Если поддомен больше не используется — удалите CNAME-запись. Если "
                        f"используется — зарегистрируйте/восстановите соответствующий ресурс на {matched_service}."
                    ),
                    owasp_category="A05:2021",
                    cwe_id="CWE-350",
                    evidence=f"CNAME: {cname_target} · признак в теле ответа: '{expected_signature}'",
                )
            ]

        return [
            ScanFinding(
                checker=self.name,
                title=f"CNAME указывает на {matched_service}, ресурс похоже занят",
                severity="info",
                description=f"CNAME → {cname_target} ({matched_service}), признаков незанятого ресурса не обнаружено.",
            )
        ]
