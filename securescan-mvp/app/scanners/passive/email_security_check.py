"""Check SPF, DMARC, and DNS resilience records using passive DNS queries."""
import dns.resolver

from app.scanners.base import BaseScanner, ScanFinding


def _first_txt_record(answers) -> str:
    return "".join(b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers)


class EmailSecurityChecker(BaseScanner):
    name = "email_security_check"

    def run(self, domain: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        findings.extend(self._check_spf(domain))
        findings.extend(self._check_dmarc(domain))
        findings.extend(self._check_dns_resilience(domain))
        return findings

    def _check_spf(self, domain: str) -> list[ScanFinding]:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            answers = []

        spf_records = []
        for answer in answers:
            record = _first_txt_record([answer])
            if record.startswith("v=spf1"):
                spf_records.append(record)

        if not spf_records:
            return [
                ScanFinding(
                    checker=self.name,
                    title="SPF-запись не найдена",
                    severity="medium",
                    description=(
                        "Без SPF любой сервер может отправлять письма от имени этого домена — "
                        "принимающие почтовые серверы не смогут отличить легитимную почту от подделки."
                    ),
                    recommendation=(
                        f'Добавьте TXT-запись на {domain} вида \'v=spf1 include:_spf.<ваш почтовый провайдер> ~all\'.'
                    ),
                    cwe_id="CWE-290",
                )
            ]

        record = spf_records[0]
        if "+all" in record:
            return [
                ScanFinding(
                    checker=self.name,
                    title="SPF настроен с '+all' (разрешает вообще любой сервер)",
                    severity="high",
                    description=f"Найденная SPF-запись: {record}. '+all' полностью обесценивает SPF.",
                    recommendation="Замените '+all' на '-all' (строгий отказ) или хотя бы '~all' (мягкий отказ).",
                    cwe_id="CWE-290",
                    evidence=record,
                )
            ]
        return [
            ScanFinding(
                checker=self.name,
                title="SPF настроен",
                severity="info",
                description=f"Найденная SPF-запись: {record}",
            )
        ]

    def _check_dmarc(self, domain: str) -> list[ScanFinding]:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5.0)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return [
                ScanFinding(
                    checker=self.name,
                    title="DMARC-запись не найдена",
                    severity="medium",
                    description=(
                        "Без DMARC даже с настроенным SPF/DKIM принимающие серверы не получают "
                        "чёткой инструкции, что делать с письмами, не прошедшими проверку — "
                        "фишинговые письма от имени домена реже попадают в спам."
                    ),
                    recommendation=f'Добавьте TXT-запись на _dmarc.{domain} вида \'v=DMARC1; p=quarantine; rua=mailto:...\'.',
                    cwe_id="CWE-290",
                )
            ]

        record = _first_txt_record(answers)
        if "p=none" in record:
            return [
                ScanFinding(
                    checker=self.name,
                    title="DMARC настроен в режиме 'p=none' (только мониторинг)",
                    severity="low",
                    description=(
                        f"Найденная DMARC-запись: {record}. 'p=none' означает, что письма, "
                        "не прошедшие проверку, всё равно доставляются — DMARC только собирает отчёты."
                    ),
                    recommendation="После оценки отчётов переключите политику на 'p=quarantine' или 'p=reject'.",
                    cwe_id="CWE-290",
                    evidence=record,
                )
            ]
        return [
            ScanFinding(
                checker=self.name,
                title="DMARC настроен с активной политикой",
                severity="info",
                description=f"Найденная DMARC-запись: {record}",
            )
        ]

    def _check_dns_resilience(self, domain: str) -> list[ScanFinding]:
        """Check NS redundancy without flagging normal multi-MX configurations."""
        findings: list[ScanFinding] = []

        try:
            ns_answers = dns.resolver.resolve(domain, "NS", lifetime=5.0)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return findings

        ns_hosts = [str(r.target).rstrip(".") for r in ns_answers]
        if len(ns_hosts) == 1:
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Слишком мало NS-записей для домена",
                    severity="low",
                    description="Единственная NS-запись — единая точка отказа: недоступность этого DNS-сервера сделает домен недоступным целиком.",
                    recommendation="Добавьте минимум две авторитативные NS-записи в разные инфраструктуры.",
                    # DNS availability and redundancy do not map cleanly to a CWE.
                    evidence=", ".join(ns_hosts),
                )
            )

        return findings
