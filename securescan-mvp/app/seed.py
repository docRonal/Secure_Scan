"""Create optional local demo data when explicitly enabled."""
import logging
import secrets
from datetime import datetime, timedelta

from app.config import settings
from app.db import SessionLocal
from app.models import (
    GUEST_USER_EMAIL, User, Asset, ScanJob, Finding, ScanType, ScanStatus,
    Severity, MonitorSchedule, VerificationMethod,
)
from app.security import hash_password

logger = logging.getLogger("securescan.seed")

# The reserved .example domain ensures demo findings cannot be mistaken for live scan results.
DEMO_DOMAIN = "demo-shop.example"


def seed_guest_user() -> None:
    if settings.auth_required:
        return

    db = SessionLocal()
    try:
        guest = db.query(User).filter(User.email == GUEST_USER_EMAIL).first()
        if guest is None:
            db.add(User(
                email=GUEST_USER_EMAIL,
                hashed_password=hash_password(secrets.token_urlsafe(48)),
            ))
            db.commit()
    finally:
        db.close()

DEMO_FINDINGS = [
    dict(checker="exposed_paths_check", title="Раскрыт чувствительный путь: /.env", severity=Severity.critical,
         description="Файл .env содержит пароли БД и API-ключи в открытом виде.",
         recommendation="Удалите /.env с продакшн-сервера или закройте доступ на уровне веб-сервера.",
         owasp_category="A05:2021", cwe_id="CWE-538"),
    dict(checker="headers_check", title="Отсутствует заголовок Strict-Transport-Security", severity=Severity.high,
         description="Ответ сервера не содержит заголовок 'Strict-Transport-Security'.",
         recommendation="Добавьте HSTS, чтобы браузеры всегда обращались к сайту по HTTPS.",
         owasp_category="A02:2021", cwe_id="CWE-693"),
    dict(checker="html_content_check", title="Форма с полем пароля отправляет данные по HTTP", severity=Severity.high,
         description="Форма входа с action=\"http://demo-shop.example/login\" содержит поле type=\"password\".",
         recommendation="Поменяйте action формы на https://.",
         owasp_category="A02:2021", cwe_id="CWE-319"),
    dict(checker="headers_check", title="Отсутствует заголовок Content-Security-Policy", severity=Severity.medium,
         description="Ответ сервера не содержит заголовок 'Content-Security-Policy'.",
         recommendation="Добавьте CSP, чтобы ограничить источники загружаемых скриптов и снизить риск XSS.",
         owasp_category="A05:2021", cwe_id="CWE-693"),
    dict(checker="tls_check", title="TLS-сертификат скоро истекает", severity=Severity.medium,
         description="Срок действия сертификата истекает через 12 дн.",
         recommendation="Запланируйте обновление сертификата заранее (например через ACME/Let's Encrypt).",
         owasp_category="A02:2021", cwe_id="CWE-298"),
    dict(checker="email_security_check", title="SPF-запись не найдена", severity=Severity.medium,
         description="TXT-запись v=spf1 для demo-shop.example не найдена — домен уязвим к спуфингу писем.",
         recommendation="Добавьте SPF-запись, перечисляющую разрешённые почтовые серверы.",
         owasp_category="A07:2021", cwe_id="CWE-290"),
    dict(checker="cookie_security_check", title="Cookie 'session_id' установлена без атрибута SameSite", severity=Severity.low,
         description="Cookie 'session_id' не ограничивает межсайтовую отправку — повышает риск CSRF.",
         recommendation="Добавьте SameSite=Lax.",
         owasp_category="A01:2021", cwe_id="CWE-352"),
    dict(checker="html_content_check", title="Внешние скрипты без Subresource Integrity (SRI): 2 шт.", severity=Severity.low,
         description="Скрипты загружаются с внешних доменов без атрибута integrity.",
         recommendation="Добавьте integrity (SHA-384 хэш) к внешним <script>.",
         owasp_category="A08:2021", cwe_id="CWE-829"),
    dict(checker="robots_disclosure_check", title="robots.txt не раскрывает путей, похожих на чувствительные", severity=Severity.info,
         description="Всего Disallow-записей: 3, ни одна не выглядит чувствительной."),
    dict(checker="tech_fingerprint", title="Обнаружена технология: nginx 1.24.0", severity=Severity.info,
         description="На основе публичного ответа сервера обнаружено использование nginx версии 1.24.0."),
]

# Older demo scan used to illustrate finding changes over time.
DEMO_FINDINGS_OLDER = DEMO_FINDINGS + [
    dict(checker="http_methods_check", title="Разрешён метод PUT", severity=Severity.medium,
         description="OPTIONS-запрос показывает, что сервер разрешает метод PUT.",
         recommendation="Отключите PUT на уровне веб-сервера, если он не используется намеренно.",
         owasp_category="A01:2021", cwe_id="CWE-650"),
    dict(checker="exposed_paths_check", title="Раскрыт .git/config", severity=Severity.high,
         description="Директория .git доступна извне — можно восстановить историю репозитория.",
         recommendation="Удалите .git из веб-корня на проде.",
         owasp_category="A05:2021", cwe_id="CWE-538"),
]


def seed_admin_user() -> None:
    if not settings.seed_admin_enabled:
        return
    if not settings.seed_admin_password:
        logger.error("SEED_ADMIN_ENABLED is true but SEED_ADMIN_PASSWORD is empty")
        return

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == settings.seed_admin_email.lower()).first()
        if existing:
            return

        user = User(
            email=settings.seed_admin_email.lower(),
            hashed_password=hash_password(settings.seed_admin_password),
        )
        db.add(user)
        db.commit()
        logger.warning(
            "Created bootstrap account %s. Disable SEED_ADMIN_ENABLED after initial provisioning.",
            settings.seed_admin_email,
        )
    finally:
        db.close()


def seed_demo_data() -> None:
    """Seed synthetic scan results and a schedule for the reserved demo domain."""
    if not settings.seed_admin_enabled or not settings.seed_demo_data_enabled:
        return
    if not settings.seed_admin_password:
        return

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == settings.seed_admin_email.lower()).first()
        if admin is None:
            return  # seed_admin_user должен был отработать раньше в main.py

        existing = (
            db.query(Asset)
            .filter(Asset.owner_id == admin.id, Asset.domain == DEMO_DOMAIN)
            .first()
        )
        if existing:
            return

        asset = Asset(
            domain=DEMO_DOMAIN,
            owner_id=admin.id,
            is_demo=True,
            is_verified=True,
            verification_method=VerificationMethod.dns_txt,
            verification_token=Asset.generate_token(),
        )
        db.add(asset)
        db.flush()  # получить asset.id до commit

        now = datetime.utcnow()

        older_scan = ScanJob(
            asset_id=asset.id,
            scan_type=ScanType.passive,
            status=ScanStatus.completed,
            progress_percent=100,
            current_step="Завершено",
            created_at=now - timedelta(days=7, minutes=3),
            started_at=now - timedelta(days=7, minutes=3),
            completed_at=now - timedelta(days=7, minutes=2),
        )
        db.add(older_scan)
        db.flush()
        for f in DEMO_FINDINGS_OLDER:
            db.add(Finding(scan_id=older_scan.id, **f))

        recent_scan = ScanJob(
            asset_id=asset.id,
            scan_type=ScanType.passive,
            status=ScanStatus.completed,
            progress_percent=100,
            current_step="Завершено",
            created_at=now - timedelta(minutes=3),
            started_at=now - timedelta(minutes=3),
            completed_at=now - timedelta(minutes=2),
        )
        db.add(recent_scan)
        db.flush()
        for f in DEMO_FINDINGS:
            db.add(Finding(scan_id=recent_scan.id, **f))

        schedule = MonitorSchedule(
            asset_id=asset.id,
            scan_type=ScanType.passive,
            frequency_hours=24,
            is_active=True,
            last_run_at=recent_scan.completed_at,
            next_run_at=now + timedelta(hours=21),  # "через 21 час" — правдоподобно для демо
        )
        db.add(schedule)

        db.commit()
        logger.warning(
            "Добавлен демо-актив %s с 2 сканами (история) и активным мониторингом для %s.",
            DEMO_DOMAIN, settings.seed_admin_email,
        )
    finally:
        db.close()
