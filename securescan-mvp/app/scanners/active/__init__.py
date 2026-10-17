"""Register the optional OWASP ZAP active scanner when explicitly enabled."""
from app.config import settings
from app.scanners.active.base import ActiveScannerPlugin

ACTIVE_SCANNERS: list[type[ActiveScannerPlugin]] = []

if settings.zap_enabled:
    from app.scanners.active.zap_scanner import ZAPActiveScanner
    ACTIVE_SCANNERS.append(ZAPActiveScanner)
