"""Run OWASP ZAP scan phases and convert alerts to application findings."""
import logging
from typing import Callable

from app.config import settings
from app.scanners.base import ScanFinding, ScanCancelled, ScanTimedOut
from app.scanners.active.base import ActiveScannerPlugin
from app.scanners.active.zap_client import ZAPClient, ZAPError, ZAPScanCancelled, ZAPTimeout

logger = logging.getLogger("securescan.active.zap")

# Map ZAP risk levels to application severity levels.
ZAP_RISK_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

# Map commonly reported CWE identifiers to OWASP Top 10 2021 categories.
CWE_TO_OWASP = {
    # A01:2021 — Broken Access Control
    "22": "A01:2021",    # Path Traversal
    "23": "A01:2021",    # Relative Path Traversal
    "35": "A01:2021",    # Path Traversal (варианты)
    "200": "A01:2021",   # Information Exposure
    "284": "A01:2021",   # Improper Access Control
    "285": "A01:2021",   # Improper Authorization
    "352": "A01:2021",   # CSRF
    "425": "A01:2021",   # Forced Browsing (Direct Request)
    "601": "A01:2021",   # Open Redirect
    "639": "A01:2021",   # IDOR
    "918": "A10:2021",   # SSRF (у OWASP вынесен в отдельную A10, не A01)

    # A02:2021 — Cryptographic Failures
    "295": "A02:2021",   # Improper Certificate Validation
    "296": "A02:2021",   # Improper Following of Certificate Chain
    "310": "A02:2021",   # Cryptographic Issues (общее)
    "319": "A02:2021",   # Cleartext Transmission
    "321": "A02:2021",   # Hardcoded Cryptographic Key
    "322": "A02:2021",
    "323": "A02:2021",
    "324": "A02:2021",   # Use of Expired Key
    "325": "A02:2021",   # Missing Cryptographic Step
    "326": "A02:2021",   # Inadequate Encryption Strength
    "327": "A02:2021",   # Broken/Risky Crypto Algorithm
    "328": "A02:2021",   # Reversible One-Way Hash
    "330": "A02:2021",   # Use of Insufficiently Random Values
    "331": "A02:2021",   # Insufficient Entropy
    "336": "A02:2021",   # Same Seed in PRNG
    "338": "A02:2021",   # Cryptographically Weak PRNG
    "757": "A02:2021",   # Selection of Less-Secure Algorithm (downgrade)

    # A03:2021 — Injection
    "20": "A03:2021",    # Improper Input Validation
    "74": "A03:2021",    # Injection (общее, "formula injection" и т.п.)
    "77": "A03:2021",    # Command Injection
    "78": "A03:2021",    # OS Command Injection
    "79": "A03:2021",    # XSS
    "80": "A03:2021",    # Improper Neutralization of Script (Basic XSS)
    "83": "A03:2021",    # XSS via <script> attribute
    "87": "A03:2021",    # XSS via Alternate Syntax
    "88": "A03:2021",    # Argument Injection
    "89": "A03:2021",    # SQL Injection
    "90": "A03:2021",    # LDAP Injection
    "91": "A03:2021",    # XML Injection
    "93": "A03:2021",    # CRLF Injection
    "94": "A03:2021",    # Code Injection
    "95": "A03:2021",    # Eval Injection
    "96": "A03:2021",    # Static Code Injection
    "97": "A03:2021",    # Server-Side Includes (SSI) Injection
    "98": "A03:2021",    # PHP File Inclusion
    "99": "A03:2021",    # Resource Injection
    "113": "A03:2021",   # HTTP Response Splitting
    "116": "A03:2021",   # Improper Output Encoding/Escaping
    "643": "A03:2021",   # XPath Injection
    "652": "A03:2021",   # XQuery Injection
    "917": "A03:2021",   # Expression Language (EL) Injection

    # A05:2021 — Security Misconfiguration
    "16": "A05:2021",    # Configuration
    "611": "A05:2021",   # XXE
    "1032": "A05:2021",  # OWASP ASVS misconfig category
    "1174": "A05:2021",

    # A06:2021 — Vulnerable and Outdated Components
    "937": "A06:2021",
    "1035": "A06:2021",
    "1104": "A06:2021",

    # A07:2021 — Identification and Authentication Failures
    "255": "A07:2021",
    "287": "A07:2021",   # Improper Authentication
    "288": "A07:2021",   # Authentication Bypass
    "290": "A07:2021",   # Authentication Bypass by Spoofing
    "294": "A07:2021",   # Auth Bypass by Capture-Replay
    "297": "A07:2021",   # Improper Certificate Validation with Host Mismatch
    "300": "A07:2021",   # Channel Accessible by Non-Endpoint
    "302": "A07:2021",   # Auth Bypass by Assumed-Immutable Data
    "304": "A07:2021",   # Missing Critical Step in Authentication
    "306": "A07:2021",   # Missing Authentication for Critical Function
    "307": "A07:2021",   # Improper Restriction of Excessive Auth Attempts
    "346": "A07:2021",   # Origin Validation Error
    "384": "A07:2021",   # Session Fixation
    "521": "A07:2021",   # Weak Password Requirements
    "613": "A07:2021",   # Insufficient Session Expiration
    "620": "A07:2021",   # Unverified Password Change
    "640": "A07:2021",   # Weak Password Recovery Mechanism
    "798": "A07:2021",   # Hardcoded Credentials
    "940": "A07:2021",   # Improper Verification of Source of a Communication

    # A08:2021 — Software and Data Integrity Failures
    "345": "A08:2021",   # Insufficient Verification of Data Authenticity
    "353": "A08:2021",   # Missing Integrity Check
    "426": "A08:2021",   # Untrusted Search Path
    "494": "A08:2021",   # Download of Code Without Integrity Check
    "502": "A08:2021",   # Insecure Deserialization
    "565": "A08:2021",   # Reliance on Cookies without Integrity Check
    "829": "A08:2021",   # Inclusion of Functionality from Untrusted Source

    # A09:2021 — Security Logging and Monitoring Failures
    "117": "A09:2021",   # Improper Output Neutralization for Logs
    "223": "A09:2021",   # Omission of Security-relevant Information
    "532": "A09:2021",   # Insertion of Sensitive Information into Log File
    "778": "A09:2021",   # Insufficient Logging
}


class ZAPActiveScanner(ActiveScannerPlugin):
    name = "zap_active_scan"

    def run(
        self,
        domain: str,
        verification_proof: str,
        should_cancel: Callable[[], bool],
        on_progress: Callable[[int, str], None] | None = None,
    ) -> list[ScanFinding]:
        target_url = f"https://{domain}/"
        client = ZAPClient(settings.zap_api_url, settings.zap_api_key)

        def report(overall_percent: int, step: str) -> None:
            if on_progress is not None:
                on_progress(overall_percent, step)

        if not client.is_available():
            raise RuntimeError(
                f"ZAP API недоступен по адресу {settings.zap_api_url}. "
                "Убедитесь, что контейнер ZAP запущен (см. app/scanners/active/README.md)."
            )

        logger.info(
            "ZAP active scan start: domain=%s verification_proof=%s...",
            domain, verification_proof[:20],
        )

        spider_id = None
        ajax_spider_started = False
        ascan_id = None
        try:
            if should_cancel():
                raise ScanCancelled(f"Активное сканирование {domain} отменено до старта")

            report(0, "Spider (краулинг)")
            spider_id = client.start_spider(target_url)
            # Reserve most progress for the longer active scan phase.
            client.wait_until_complete(
                client.spider_status, spider_id,
                settings.zap_poll_interval_seconds, settings.zap_max_wait_seconds,
                should_cancel=should_cancel,
                on_progress=lambda p: report(int(p * 0.3), "Spider (краулинг)"),
            )

            if settings.zap_ajax_spider_enabled:
                try:
                    report(30, "AJAX Spider (JavaScript-маршруты)")
                    client.start_ajax_spider(target_url)
                    ajax_spider_started = True
                    client.wait_until_complete(
                        client.ajax_spider_status, target_url,
                        settings.zap_poll_interval_seconds, settings.zap_max_wait_seconds,
                        should_cancel=should_cancel,
                        on_progress=lambda p: report(
                            30 + int(p * 0.1), "AJAX Spider (JavaScript-маршруты)"
                        ),
                    )
                except ZAPError:
                    logger.warning(
                        "AJAX Spider недоступен в текущей сборке ZAP для %s; "
                        "продолжаем обычный active scan",
                        domain,
                    )

            report(40 if settings.zap_ajax_spider_enabled else 30, "Active scan (тестирование)")
            policy_name = settings.zap_scan_policy
            client.configure_scan_policy(
                policy_name,
                attack_strength=settings.zap_attack_strength,
                alert_threshold=settings.zap_alert_threshold,
                enable_all_scanners=settings.zap_enable_all_scanners,
            )
            ascan_id = client.start_active_scan(target_url, policy_name)
            client.wait_until_complete(
                client.ascan_status, ascan_id,
                settings.zap_poll_interval_seconds, settings.zap_max_wait_seconds,
                should_cancel=should_cancel,
                on_progress=lambda p: report(
                    (40 if settings.zap_ajax_spider_enabled else 30)
                    + int(p * (0.6 if settings.zap_ajax_spider_enabled else 0.7)),
                    "Active scan (тестирование)",
                ),
            )

            raw_alerts = client.get_alerts(target_url)
            report(100, "Завершено")

        except (ZAPScanCancelled, ZAPTimeout) as exc:
            # Stop the current ZAP phase so it cannot keep running after cancellation.
            try:
                if ascan_id is not None:
                    client.stop_active_scan(ascan_id)
                elif ajax_spider_started:
                    client.stop_ajax_spider()
                elif spider_id is not None:
                    client.stop_spider(spider_id)
            except ZAPError:
                logger.warning("Не удалось сразу остановить ZAP для %s", domain)

            if ascan_id is not None:
                try:
                    client.wait_until_complete(
                        client.ascan_status,
                        ascan_id,
                        poll_interval=1,
                        max_wait=20,
                    )
                except (ZAPTimeout, ZAPError) as stop_wait_error:
                    logger.warning("ZAP scan stop is still pending for %s", domain)
                    logger.debug("ZAP stop wait detail: %s", stop_wait_error)

            # Keep complete pages even if ZAP times out while serving a later page.
            raw_alerts = self._get_partial_alerts(client, target_url)
            partial_findings = [self._to_finding(alert) for alert in raw_alerts]
            partial_findings.extend(self._add_contextual_findings(target_url, raw_alerts))
            logger.info("Collected %d partial ZAP alerts for %s", len(raw_alerts), domain)

            if isinstance(exc, ZAPScanCancelled):
                raise ScanCancelled(
                    f"Активное сканирование {domain} отменено пользователем "
                    f"({len(partial_findings)} находок сохранено)",
                    partial_findings=partial_findings,
                ) from exc
            else:
                raise ScanTimedOut(
                    f"Активное сканирование {domain} не уложилось в отведённое время "
                    f"(прогресс {exc.last_progress}%, {len(partial_findings)} находок сохранено). "
                    "Увеличьте ZAP_MAX_WAIT_SECONDS для больших сайтов.",
                    partial_findings=partial_findings,
                ) from exc

        except ZAPError as exc:
            raise RuntimeError(f"Ошибка ZAP-сканирования для {domain}: {exc}") from exc

        findings = [self._to_finding(a) for a in raw_alerts]
        findings.extend(self._add_contextual_findings(target_url, raw_alerts))
        return findings

    @staticmethod
    def _get_partial_alerts(
        client: ZAPClient,
        target_url: str,
        *,
        page_size: int = 100,
        max_pages: int = 10,
    ) -> list[dict]:
        alerts: list[dict] = []
        for page in range(max_pages):
            try:
                page_alerts = client.get_alerts(
                    target_url,
                    timeout=10.0,
                    start=page * page_size,
                    count=page_size,
                )
            except ZAPError as exc:
                logger.warning(
                    "ZAP alert retrieval stopped after %d partial alerts: %s",
                    len(alerts),
                    exc,
                )
                break

            alerts.extend(page_alerts)
            if len(page_alerts) < page_size:
                break
        return alerts

    @staticmethod
    def _add_contextual_findings(target_url: str, raw_alerts: list[dict]) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        alert_titles = {str(alert.get("alert", "")).lower() for alert in raw_alerts}
        evidence_text = " | ".join(
            sorted({str(alert.get("url") or "") for alert in raw_alerts if alert.get("url")})
        )

        if any("sql" in title or "injection" in title for title in alert_titles):
            findings.append(
                ScanFinding(
                    checker="zap_active_scan",
                    title="Активный ZAP-скан обнаружил признаки инъекций",
                    severity="high",
                    description="ZAP сообщил о потенциальных SQL/HTML/command injection-паттернах, которые требуют ручной проверки.",
                    recommendation="Проверьте обработку входных параметров, параметризуйте запросы и экранируйте вывод.",
                    owasp_category="A03:2021",
                    # The alert may describe non-SQL injection, so avoid assigning CWE-89.
                    cwe_id=None,
                    evidence=evidence_text or None,
                )
            )

        if any("redirect" in title for title in alert_titles):
            findings.append(
                ScanFinding(
                    checker="zap_active_scan",
                    title="Обнаружен риск open redirect",
                    severity="medium",
                    description="ZAP нашёл алерты, связанные с перенаправлениями, что может позволить злоумышленнику вынудить пользователя перейти на внешнюю страницу.",
                    recommendation="Разрешайте перенаправления только на доверенный allow-list и избегайте пользовательского ввода в Location.",
                    owasp_category="A01:2021",
                    cwe_id="CWE-601",
                    evidence=evidence_text or None,
                )
            )

        if any("csrf" in title for title in alert_titles):
            findings.append(
                ScanFinding(
                    checker="zap_active_scan",
                    title="Обнаружен риск CSRF",
                    severity="medium",
                    description="ZAP выявил уязвимости, связанные с CSRF, которые позволяют выполняться неавторизованным действиям от имени пользователя.",
                    recommendation="Добавьте CSRF-токен и проверку Origin/Referer для чувствительных операций.",
                    owasp_category="A01:2021",
                    cwe_id="CWE-352",
                    evidence=evidence_text or None,
                )
            )

        if any("ssrf" in title for title in alert_titles) or any("server-side request" in title for title in alert_titles):
            findings.append(
                ScanFinding(
                    checker="zap_active_scan",
                    title="Обнаружен риск SSRF",
                    severity="high",
                    description="ZAP отметил SSRF-подобные векторы, которые могут позволить серверу отправлять запросы к внутренним ресурсам.",
                    recommendation="Ограничьте доступ к внутренним адресам, блокируйте localhost/169.254.0.0/16 и проверяйте входные URL.",
                    owasp_category="A10:2021",
                    cwe_id="CWE-918",
                    evidence=evidence_text or None,
                )
            )

        if any("session" in title for title in alert_titles) or any("cookie" in title for title in alert_titles):
            findings.append(
                ScanFinding(
                    checker="zap_active_scan",
                    title="Обнаружены проблемы с обработкой сессий/куки",
                    severity="medium",
                    description="ZAP сообщил о слабостях, связанных с cookie или сессиями, что повышает риск кражи или подмены сессии.",
                    recommendation="Проверьте Secure/HttpOnly/SameSite и истечение сессий, а также защиту от фиксации сессии.",
                    owasp_category="A07:2021",
                    cwe_id="CWE-384",
                    evidence=evidence_text or None,
                )
            )

        if any("path traversal" in title or "file inclusion" in title for title in alert_titles):
            findings.append(
                ScanFinding(
                    checker="zap_active_scan",
                    title="Обнаружены признаки path traversal / file inclusion",
                    severity="high",
                    description="ZAP выявил векторы обхода путей или включения файлов, которые могут раскрывать внутренние ресурсы.",
                    recommendation="Нормализуйте пути, запрещайте traversal-символы и не включайте пользовательский путь без белого списка.",
                    owasp_category="A01:2021",
                    cwe_id="CWE-22",
                    evidence=evidence_text or None,
                )
            )

        return findings

    @staticmethod
    def _to_finding(alert: dict) -> ScanFinding:
        cwe_id_raw = str(alert.get("cweid", "")).strip()
        cwe_id = f"CWE-{cwe_id_raw}" if cwe_id_raw and cwe_id_raw not in ("-1", "0") else None
        description = _strip_html(alert.get("description", ""))
        confidence = str(alert.get("confidence") or "").strip()
        other_info = _strip_html(alert.get("otherinfo", ""))
        details = [description] if description else []
        if confidence:
            details.append(f"Confidence: {confidence}")
        if other_info:
            details.append(f"Additional details: {other_info[:500]}")

        evidence_parts: list[str] = []
        instances = alert.get("instances") or []
        for instance in instances[:3]:
            parts = []
            method = str(instance.get("method") or "").strip()
            uri = str(instance.get("uri") or instance.get("url") or "").strip()
            if method or uri:
                parts.append(" ".join(value for value in (method, uri) if value))
            for key in ("param", "attack", "evidence"):
                value = str(instance.get(key) or "").strip()
                if value:
                    parts.append(f"{key}={value[:300]}")
            if parts:
                evidence_parts.append("; ".join(parts))

        if not evidence_parts:
            fallback_evidence = alert.get("evidence") or alert.get("url")
            if fallback_evidence:
                evidence_parts.append(str(fallback_evidence)[:900])

        return ScanFinding(
            checker="zap_active_scan",
            title=alert.get("alert", "ZAP alert"),
            severity=ZAP_RISK_MAP.get(alert.get("risk"), "info"),
            description="\n\n".join(details),
            recommendation=_strip_html(alert.get("solution", "")) or None,
            owasp_category=CWE_TO_OWASP.get(cwe_id_raw),
            cwe_id=cwe_id,
            evidence="\n".join(evidence_parts) or None,
        )


def _strip_html(text: str) -> str:
    """Strip HTML tags from ZAP text fields."""
    import re
    return re.sub(r"<[^>]+>", " ", text or "").strip()
