"""Centralized application settings loaded from environment variables."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "SecureScan AI (MVP)"
    database_url: str = "sqlite:///./securescan.db"

    # Keep passive checks bounded to avoid unnecessary load on targets.
    http_timeout_seconds: float = 8.0
    http_user_agent: str = "SecureScanAI-Bot/0.1 (+https://securescan.ai/bot)"
    max_concurrent_requests_per_target: int = 2

    jwt_secret_key: str
    jwt_expires_minutes: int = 60 * 24 * 7
    auth_required: bool = True
    public_registration_enabled: bool = False

    # Demo account seeding is for local development only.
    seed_admin_enabled: bool = False
    seed_admin_email: str = "local-admin@example.invalid"
    seed_admin_password: str | None = None
    seed_demo_data_enabled: bool = False

    # This in-memory scan limit is process-local and resets on restart.
    scan_rate_limit_per_hour: int = 20

    # Asset ownership verification
    verification_token_prefix: str = "securescan-verify"

    # Development dashboard origins; restrict these in production.
    cors_allowed_origins: list[str] = [
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:8081", "http://127.0.0.1:8081",
    ]

    # Active scans send real test payloads and require verified asset ownership.
    zap_enabled: bool = False
    zap_api_url: str = "http://127.0.0.1:8080"
    zap_api_key: str | None = None
    # Leave the built-in ZAP policy unchanged unless a custom policy is configured.
    zap_scan_policy: str | None = None
    # Supported attack strengths are Low, Medium, and High.
    zap_attack_strength: str = "High"
    zap_alert_threshold: str = "Low"
    zap_enable_all_scanners: bool = True
    zap_ajax_spider_enabled: bool = True
    zap_poll_interval_seconds: float = 2.0
    zap_max_wait_seconds: int = 7200

    class Config:
        env_file = ".env"


settings = Settings()
