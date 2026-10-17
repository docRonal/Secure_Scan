import enum
import ipaddress
import re
import secrets
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, ForeignKey, Text,
    Enum as SAEnum, UniqueConstraint,
)
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field, ConfigDict, field_validator

from app.db import Base
from app.config import settings


class VerificationMethod(str, enum.Enum):
    dns_txt = "dns_txt"
    meta_tag = "meta_tag"
    file_token = "file_token"


class ScanType(str, enum.Enum):
    passive = "passive"
    active = "active"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    blocked_unverified = "blocked_unverified"
    cancelled = "cancelled"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---------------------------------------------------------------- ORM ----

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    assets = relationship("Asset", back_populates="owner")

    @property
    def is_guest(self) -> bool:
        return self.email == GUEST_USER_EMAIL


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        # A domain is unique per owner, not globally.
        UniqueConstraint("owner_id", "domain", name="uq_asset_owner_domain"),
    )

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_verified = Column(Boolean, default=False)
    is_demo = Column(Boolean, nullable=False, default=False)
    verification_token = Column(String, nullable=False)
    verification_method = Column(SAEnum(VerificationMethod), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="assets")
    scans = relationship("ScanJob", back_populates="asset")

    @staticmethod
    def generate_token() -> str:
        return f"{settings.verification_token_prefix}={secrets.token_hex(16)}"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scan_type = Column(SAEnum(ScanType), nullable=False, default=ScanType.passive)
    status = Column(SAEnum(ScanStatus), nullable=False, default=ScanStatus.queued)
    cancel_requested = Column(Boolean, nullable=False, default=False)
    progress_percent = Column(Integer, nullable=False, default=0)
    current_step = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    checker = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(SAEnum(Severity), nullable=False, default=Severity.info)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    owasp_category = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)

    scan = relationship("ScanJob", back_populates="findings")


class MonitorSchedule(Base):
    """Scheduled recurring scans and their monitoring state."""
    __tablename__ = "monitor_schedules"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scan_type = Column(SAEnum(ScanType), nullable=False, default=ScanType.passive)
    frequency_hours = Column(Integer, nullable=False, default=24)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=False)

    asset = relationship("Asset")


# ------------------------------------------------------------ Schemas ----

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class AssetCreate(BaseModel):
    domain: str = Field(..., examples=["example.com"])

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        """Normalize a domain or URL to a validated hostname."""
        v = v.strip().lower()
        v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
        v = v.split("/")[0]
        v = v.split("?")[0].split("#")[0]
        v = v.split(":")[0]
        v = v.rstrip(".")

        try:
            ipaddress.ip_address(v)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses are not accepted; provide a domain name")

        if not DOMAIN_PATTERN.match(v):
            raise ValueError(
                f"'{v}' не похож на домен верхнего уровня (ожидается что-то вроде "
                f"example.com, без пути и без параметров)"
            )
        return v


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    is_verified: bool
    is_demo: bool = False
    verification_token: str
    verification_method: VerificationMethod | None = None


class ScanCreate(BaseModel):
    asset_id: int
    scan_type: ScanType = ScanType.passive


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    checker: str
    title: str
    severity: Severity
    description: str
    recommendation: str | None = None
    owasp_category: str | None = None
    cwe_id: str | None = None
    evidence: str | None = None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    scan_type: ScanType
    status: ScanStatus
    cancel_requested: bool = False
    progress_percent: int = 0
    current_step: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    findings: list[FindingOut] = []


class MonitorScheduleCreate(BaseModel):
    asset_id: int
    scan_type: ScanType = ScanType.passive
    frequency_hours: int = Field(default=24, ge=1, le=24 * 30, description="1 ч. – 30 дн.")


class MonitorScheduleUpdate(BaseModel):
    is_active: bool | None = None
    frequency_hours: int | None = Field(default=None, ge=1, le=24 * 30)


class MonitorScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    scan_type: ScanType
    frequency_hours: int
    is_active: bool
    last_run_at: datetime | None = None
    next_run_at: datetime


# --------------------------------------------------------------- Auth ----

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
GUEST_USER_EMAIL = "guest@local.invalid"


class UserCreate(BaseModel):
    email: str = Field(..., pattern=EMAIL_PATTERN, examples=["you@example.com"])
    password: str = Field(..., min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: str = Field(..., pattern=EMAIL_PATTERN)
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    created_at: datetime
    is_guest: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
