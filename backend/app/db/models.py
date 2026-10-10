import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.crypto import get_cipher


def utcnow() -> datetime:
    return datetime.now(UTC)


class EncryptedText(TypeDecorator):
    """Text column transparently encrypted with the hybrid AES-256-GCM / X25519+ML-KEM-768 cipher."""

    impl = Text
    cache_ok = True

    def __init__(self, context: str = "", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = context

    def process_bind_param(self, value, dialect):
        return None if value is None else get_cipher().encrypt(value, self.context)

    def process_result_value(self, value, dialect):
        return None if value is None else get_cipher().decrypt(value, self.context)


def _enum(cls: type[enum.Enum], name: str) -> Enum:
    return Enum(cls, name=name, values_callable=lambda e: [m.value for m in e])


class Base(DeclarativeBase):
    pass


class Role(enum.StrEnum):
    USER = "user"
    ADVANCED = "advanced"
    ADMIN = "admin"


ROLE_RANK = {Role.USER: 1, Role.ADVANCED: 2, Role.ADMIN: 3}


class UserStatus(enum.StrEnum):
    ACTIVE = "active"
    PENDING = "pending"  # SSO/LDAP account awaiting admin validation
    DISABLED = "disabled"


class AuthSource(enum.StrEnum):
    LOCAL = "local"
    OIDC = "oidc"
    LDAP = "ldap"
    SERVICE = "service"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("auth_source", "external_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(EncryptedText("user.email"), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    role: Mapped[Role] = mapped_column(_enum(Role, "role"), default=Role.USER)
    status: Mapped[UserStatus] = mapped_column(_enum(UserStatus, "user_status"), default=UserStatus.ACTIVE)
    auth_source: Mapped[AuthSource] = mapped_column(_enum(AuthSource, "auth_source"), default=AuthSource.LOCAL)
    external_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(EncryptedText("user.totp"), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int] = mapped_column(BigInteger, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA3-256 of the cookie value
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    mfa_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    prefix: Mapped[str] = mapped_column(String(16))
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)  # SHA3-256
    scope: Mapped[str] = mapped_column(String(16), default="write")  # "read" (read-only) or "write"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    name: Mapped[str] = mapped_column(String(128), default="Security key")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthFlow(Base):
    """Short-lived, single-use state for OIDC (state/nonce/PKCE) and WebAuthn challenges."""

    __tablename__ = "auth_flows"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA3-256 of state / challenge key
    kind: Mapped[str] = mapped_column(String(32))
    data: Mapped[str] = mapped_column(EncryptedText("auth_flow"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class AppSetting(Base):
    """Non-secret runtime settings editable by administrators."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | list | str | int | bool | None] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class SecretSetting(Base):
    """Secret runtime settings (e.g. AI API keys) — encrypted at rest, never returned by the API."""

    __tablename__ = "secret_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(EncryptedText("secret_setting"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class GroupMapping(Base):
    __tablename__ = "group_mappings"
    __table_args__ = (UniqueConstraint("source", "group"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(16))  # oidc | ldap
    group: Mapped[str] = mapped_column(String(512))
    role: Mapped[Role] = mapped_column(_enum(Role, "role"))


class Pipeline(Base):
    """Project: configuration + sample logs + agent instructions, encrypted at rest.

    `version` implements optimistic locking: concurrent editors cannot silently overwrite each other."""

    __tablename__ = "pipelines"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    config: Mapped[str] = mapped_column(EncryptedText("pipeline.config"))
    sample: Mapped[str | None] = mapped_column(EncryptedText("pipeline.sample"), nullable=True)
    input_format: Mapped[str] = mapped_column(String(16), default="lines")
    instructions: Mapped[str | None] = mapped_column(EncryptedText("pipeline.instructions"), nullable=True)
    expected_output: Mapped[str | None] = mapped_column(EncryptedText("pipeline.expected"), nullable=True)
    # JSON object of simulated input fields (see app.core.input_fields).
    input_fields: Mapped[str | None] = mapped_column(EncryptedText("pipeline.input_fields"), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    updated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SharePermission(enum.StrEnum):
    READ = "read"
    WRITE = "write"


class PipelineShare(Base):
    """A project shared by its owner with a colleague (read-only or read-write)."""

    __tablename__ = "pipeline_shares"
    __table_args__ = (UniqueConstraint("pipeline_id", "user_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pipeline_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("pipelines.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    permission: Mapped[SharePermission] = mapped_column(_enum(SharePermission, "share_permission"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserGroup(Base):
    """Directory groups of a user, as asserted by the IdP / LDAPS at the user's last login."""

    __tablename__ = "user_groups"
    __table_args__ = (UniqueConstraint("user_id", "source", "group"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(16))  # oidc | ldap
    group: Mapped[str] = mapped_column(String(512))
    group_key: Mapped[str] = mapped_column(String(512), index=True)  # lower-cased, for matching
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PipelineGroupShare(Base):
    """A project shared with every member of a directory group."""

    __tablename__ = "pipeline_group_shares"
    __table_args__ = (UniqueConstraint("pipeline_id", "source", "group_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pipeline_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("pipelines.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(16))
    group: Mapped[str] = mapped_column(String(512))
    group_key: Mapped[str] = mapped_column(String(512), index=True)
    permission: Mapped[SharePermission] = mapped_column(_enum(SharePermission, "share_permission"))
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
