"""Match detected technology versions against known vulnerability data."""
from app.scanners.base import BaseScanner, ScanFinding
from app.scanners.passive.tech_fingerprint import TechFingerprintChecker
from app.vulnerability_db.cve_client import query_nvd, offline_lookup


class OutdatedComponentsChecker(BaseScanner):
    name = "outdated_components"

    def run(self, domain: str) -> list[ScanFinding]:
        fingerprint_findings = TechFingerprintChecker().run(domain)
        findings: list[ScanFinding] = []

        for f in fingerprint_findings:
            if not f.evidence or "=" not in f.evidence:
                continue
            product, version = f.evidence.split("=", 1)
            if version == "unknown":
                continue

            matches = query_nvd(product, version)
            if not matches:
                matches = offline_lookup(product)

            for m in matches:
                findings.append(
                    ScanFinding(
                        checker=self.name,
                        title=f"Известная уязвимость в {product} {version}: {m.identifier}",
                        severity=m.severity,
                        description=m.summary or "См. идентификатор уязвимости для деталей.",
                        recommendation=f"Обновите {product} до последней стабильной версии.",
                        owasp_category="A06:2021",
                        cwe_id=None,
                        evidence=m.identifier,
                    )
                )

        if not findings:
            findings.append(
                ScanFinding(
                    checker=self.name,
                    title="Известных уязвимостей в обнаруженных версиях не найдено",
                    severity="info",
                    description=(
                        "По результатам сверки с базой NVD для обнаруженных технологий "
                        "известных уязвимостей не найдено. Это не гарантия отсутствия "
                        "уязвимостей — только отсутствие совпадений в проверенной базе."
                    ),
                )
            )

        return findings
