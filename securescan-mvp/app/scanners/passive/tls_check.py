"""Inspect TLS certificate validity, protocol version, cipher, and expiry."""
import socket
import ssl
from datetime import datetime, timezone

from app.scanners.base import BaseScanner, ScanFinding

DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
CERT_EXPIRY_WARNING_DAYS = 30

# Treat legacy or null ciphers as findings; modern servers should not negotiate them.
WEAK_CIPHER_MARKERS = ("RC4", "DES", "NULL", "EXPORT", "MD5", "anon")


class TLSChecker(BaseScanner):
    name = "tls_check"

    def run(self, domain: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    protocol = ssock.version()
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()  # (name, protocol_version, secret_bits) | None

        except ssl.SSLCertVerificationError as exc:
            # Report certificate validation failures separately from connectivity errors.
            return [
                ScanFinding(
                    checker=self.name,
                    title="TLS-сертификат не прошёл проверку доверия",
                    severity="high",
                    description=(
                        f"Браузер отклонит соединение с предупреждением о недоверенном "
                        f"сертификате: {getattr(exc, 'verify_message', None) or exc}."
                    ),
                    recommendation=(
                        "Убедитесь, что сертификат выпущен доверенным CA (например через "
                        "Let's Encrypt), цепочка полная, а имя хоста совпадает с доменом."
                    ),
                    owasp_category="A02:2021",
                    cwe_id="CWE-295",
                    evidence=str(exc),
                )
            ]

        except (socket.timeout, socket.gaierror, ConnectionRefusedError, ssl.SSLError) as exc:
            return [
                ScanFinding(
                    checker=self.name,
                    title="Не удалось установить TLS-соединение на порт 443",
                    severity="info",
                    description=f"Ошибка при подключении: {exc}",
                )
            ]

        if protocol in DEPRECATED_PROTOCOLS:
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title=f"Используется устаревший протокол {protocol}",
                    severity="high",
                    description=f"Сервер согласовал устаревший и небезопасный протокол {protocol}.",
                    recommendation="Отключите TLS 1.0/1.1/SSLv2/SSLv3, оставьте только TLS 1.2+.",
                    owasp_category="A02:2021",
                    cwe_id="CWE-327",
                    evidence=f"Negotiated protocol: {protocol}",
                )
            )

        if cipher:
            cipher_name = cipher[0]
            secret_bits = cipher[2] if len(cipher) > 2 else None
            is_weak_name = any(marker in cipher_name.upper() for marker in WEAK_CIPHER_MARKERS)
            is_weak_strength = isinstance(secret_bits, int) and secret_bits < 112  # ниже 3DES-эквивалента
            if is_weak_name or is_weak_strength:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Согласован слабый шифр: {cipher_name}",
                        severity="high",
                        description=(
                            f"Сервер согласовал устаревший/слабый шифр {cipher_name}"
                            + (f" ({secret_bits} бит)" if secret_bits else "") + "."
                        ),
                        recommendation="Отключите поддержку RC4/DES/3DES/экспортных и анонимных шифров на веб-сервере.",
                        owasp_category="A02:2021",
                        cwe_id="CWE-327",
                        evidence=f"Negotiated cipher: {cipher_name}",
                    )
                )

        not_after = cert.get("notAfter") if cert else None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title="TLS-сертификат просрочен",
                        severity="critical",
                        description=f"Срок действия сертификата истёк {expiry.date()}.",
                        recommendation="Немедленно обновите TLS-сертификат.",
                        owasp_category="A02:2021",
                        cwe_id="CWE-298",
                    )
                )
            elif days_left < CERT_EXPIRY_WARNING_DAYS:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title="TLS-сертификат скоро истекает",
                        severity="medium",
                        description=f"Срок действия сертификата истекает через {days_left} дн. ({expiry.date()}).",
                        recommendation="Запланируйте обновление сертификата заранее (в идеале — через автопродление, например ACME/Let's Encrypt).",
                        owasp_category="A02:2021",
                        cwe_id="CWE-298",
                    )
                )

        if not findings:
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Существенных проблем с TLS-конфигурацией не найдено",
                    severity="info",
                    description=(
                        f"Сертификат доверен, протокол {protocol}, шифр "
                        f"{cipher[0] if cipher else 'неизвестен'} — заметных проблем нет."
                    ),
                )
            )

        return findings
