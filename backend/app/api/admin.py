"""Administration: users & roles, service accounts, runtime settings, group mappings, AI agent,
PKI injection, audit trail (with export)."""

import csv
import io
import json
import re
import secrets
import string
import uuid
from datetime import datetime
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import TokenIn, user_out
from app.core import syslog
from app.core.config import get_settings
from app.core.deps import Principal, require_role
from app.core.security import hash_password
from app.db.models import AuditLog, AuthSource, GroupMapping, Role, User, UserStatus, WebAuthnCredential
from app.db.session import get_db
from app.services.audit import audit
from app.services.llm import LLMError, chat, list_models, load_llm_config
from app.services.sessions import revoke_all_sessions
from app.services.settings_store import (
    apply_syslog_settings,
    get_secret_setting,
    get_setting,
    load_syslog_target,
    put_secret_setting,
    put_setting,
)
from app.services.tokens import create_token, list_tokens, revoke_token, token_out

router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_only = require_role(Role.ADMIN)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{2,128}$")


def _temp_password() -> str:
    alphabet = string.ascii_letters + string.digits + "-_.!@#%"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(20))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


async def _get_user(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    return user


async def _active_admins(db: AsyncSession) -> int:
    return (
        await db.execute(select(func.count()).where(User.role == Role.ADMIN, User.status == UserStatus.ACTIVE))
    ).scalar_one()


# ---- Users -----------------------------------------------------------------------------------
class UserCreate(BaseModel):
    username: str = Field(max_length=128)
    display_name: str | None = Field(default=None, max_length=256)
    email: str | None = Field(default=None, max_length=256)
    role: Role = Role.USER
    service_account: bool = False


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=256)
    email: str | None = Field(default=None, max_length=256)
    role: Role | None = None
    status: UserStatus | None = None


@router.get("/users")
async def users(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = (await db.execute(select(User).order_by(User.username))).scalars()
    return [user_out(u) for u in rows]


@router.post("/users")
async def user_create(
    body: UserCreate, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    if not USERNAME_RE.match(body.username):
        raise HTTPException(422, "Invalid username")
    temp = None if body.service_account else _temp_password()
    user = User(
        username=body.username,
        display_name=body.display_name,
        email=body.email,
        role=body.role,
        auth_source=AuthSource.SERVICE if body.service_account else AuthSource.LOCAL,
        password_hash=hash_password(temp) if temp else None,
        must_change_password=not body.service_account,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(409, "Username already exists") from exc
    await audit(
        db,
        "user.create",
        request=request,
        actor=principal.user,
        target=user.username,
        details={"role": user.role, "service_account": body.service_account},
    )
    await db.commit()
    return {"user": user_out(user), "temporary_password": temp}


@router.patch("/users/{user_id}")
async def user_update(
    user_id: uuid.UUID,
    body: UserPatch,
    request: Request,
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await _get_user(db, user_id)
    changes = body.model_dump(exclude_unset=True)
    demoting = ("role" in changes and changes["role"] != Role.ADMIN) or (
        "status" in changes and changes["status"] != UserStatus.ACTIVE
    )
    if user.role == Role.ADMIN and demoting and await _active_admins(db) <= 1:
        raise HTTPException(409, "Cannot remove the last active administrator")
    before = {"role": user.role, "status": user.status}
    for key, value in changes.items():
        setattr(user, key, value)
    if changes.get("status") == UserStatus.DISABLED:
        await revoke_all_sessions(db, user.id)
    action = "user.rights_change" if {"role", "status"} & changes.keys() else "user.update"
    await audit(
        db,
        action,
        request=request,
        actor=principal.user,
        target=user.username,
        details={"before": before, "changes": {k: str(v) for k, v in changes.items()}},
    )
    await db.commit()
    return user_out(user)


@router.post("/users/{user_id}/reset-password")
async def user_reset_password(
    user_id: uuid.UUID, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    user = await _get_user(db, user_id)
    if user.auth_source != AuthSource.LOCAL:
        raise HTTPException(400, "Only local accounts have a password")
    temp = _temp_password()
    user.password_hash = hash_password(temp)
    user.must_change_password = True
    user.failed_attempts = 0
    user.locked_until = None
    await revoke_all_sessions(db, user.id)
    await audit(db, "user.password_reset", request=request, actor=principal.user, target=user.username)
    await db.commit()
    return {"temporary_password": temp}


@router.post("/users/{user_id}/unlock")
async def user_unlock(
    user_id: uuid.UUID, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    user = await _get_user(db, user_id)
    user.failed_attempts = 0
    user.locked_until = None
    await audit(db, "user.unlock", request=request, actor=principal.user, target=user.username)
    await db.commit()
    return user_out(user)


@router.post("/users/{user_id}/reset-mfa")
async def user_reset_mfa(
    user_id: uuid.UUID, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    user = await _get_user(db, user_id)
    user.totp_enabled = False
    user.totp_secret = None
    await db.execute(delete(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))
    await revoke_all_sessions(db, user.id)
    await audit(db, "user.mfa_reset", request=request, actor=principal.user, target=user.username)
    await db.commit()
    return user_out(user)


@router.delete("/users/{user_id}")
async def user_delete(
    user_id: uuid.UUID, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    user = await _get_user(db, user_id)
    if user.id == principal.user.id:
        raise HTTPException(409, "You cannot delete your own account")
    if user.role == Role.ADMIN and await _active_admins(db) <= 1:
        raise HTTPException(409, "Cannot delete the last active administrator")
    await db.delete(user)
    await audit(db, "user.delete", request=request, actor=principal.user, target=user.username)
    await db.commit()
    return {"ok": True}


# ---- Service account tokens -------------------------------------------------------------------
@router.get("/users/{user_id}/tokens")
async def user_tokens(
    user_id: uuid.UUID, _: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    await _get_user(db, user_id)
    return await list_tokens(db, user_id)


@router.post("/users/{user_id}/tokens")
async def user_token_create(
    user_id: uuid.UUID,
    body: TokenIn,
    request: Request,
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await _get_user(db, user_id)
    if user.auth_source != AuthSource.SERVICE:
        raise HTTPException(400, "Tokens can be issued here only for service accounts")
    token, raw = await create_token(db, user.id, body.name, body.expires_in_days)
    await audit(
        db,
        "token.create",
        request=request,
        actor=principal.user,
        target=f"{user.username}:{token.name}",
        details={"expires_at": token.expires_at.isoformat()},
    )
    await db.commit()
    return {**token_out(token), "token": raw}


@router.delete("/users/{user_id}/tokens/{token_id}")
async def user_token_revoke(
    user_id: uuid.UUID,
    token_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> dict:
    token = await revoke_token(db, user_id, token_id)
    if token is None:
        raise HTTPException(404, "Not found")
    await audit(db, "token.revoke", request=request, actor=principal.user, target=token.name)
    await db.commit()
    return {"ok": True}


# ---- Runtime settings ------------------------------------------------------------------------
class LoggingSettings(BaseModel):
    masking_enabled: bool
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class ProvisioningSettings(BaseModel):
    auto_provisioning: bool
    default_role: Role


SETTINGS_MODELS = {"logging": LoggingSettings, "provisioning": ProvisioningSettings}


@router.get("/settings")
async def settings_get(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    s = get_settings()
    return {
        **{k: await get_setting(db, k) for k in SETTINGS_MODELS},
        "system": {
            "oidc_enabled": s.oidc_enabled,
            "ldap_enabled": s.ldap_enabled,
            "secrets_backend": s.secrets_backend,
            "session_idle_minutes": s.session_idle_minutes,
            "lockout_threshold": s.lockout_threshold,
            "inactive_account_days": s.inactive_account_days,
            "backup_retention_days": s.backup_retention_days,
        },
    }


@router.put("/settings/{key}")
async def settings_put(
    key: str,
    body: dict,
    request: Request,
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> dict:
    model = SETTINGS_MODELS.get(key)
    if model is None:
        raise HTTPException(404, "Unknown settings section")
    value = model.model_validate(body).model_dump(mode="json")
    result = await put_setting(db, key, value, principal.user.username)
    await audit(db, "settings.update", request=request, actor=principal.user, target=key, details=value)
    await db.commit()
    return result


# ---- Group mappings --------------------------------------------------------------------------
class MappingIn(BaseModel):
    source: Literal["oidc", "ldap"]
    group: str = Field(min_length=1, max_length=512)
    role: Role


@router.get("/group-mappings")
async def mappings(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = (await db.execute(select(GroupMapping).order_by(GroupMapping.source, GroupMapping.group))).scalars()
    return [{"id": m.id, "source": m.source, "group": m.group, "role": m.role.value} for m in rows]


@router.post("/group-mappings")
async def mapping_create(
    body: MappingIn, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    m = GroupMapping(source=body.source, group=body.group, role=body.role)
    db.add(m)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(409, "Mapping already exists") from exc
    await audit(
        db,
        "rights.group_mapping_create",
        request=request,
        actor=principal.user,
        target=f"{body.source}:{body.group}",
        details={"role": body.role},
    )
    await db.commit()
    return {"id": m.id}


@router.delete("/group-mappings/{mapping_id}")
async def mapping_delete(
    mapping_id: int, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    m = await db.get(GroupMapping, mapping_id)
    if m is None:
        raise HTTPException(404, "Not found")
    await db.delete(m)
    await audit(
        db, "rights.group_mapping_delete", request=request, actor=principal.user, target=f"{m.source}:{m.group}"
    )
    await db.commit()
    return {"ok": True}


# ---- AI agent configuration ------------------------------------------------------------------
class AIConfigIn(BaseModel):
    provider: Literal["ollama", "openai"]
    base_url: str = Field(pattern=r"^https?://", max_length=512)
    model: str = Field(min_length=1, max_length=128)
    temperature: float = Field(ge=0, le=2)
    timeout_s: int = Field(ge=5, le=900)
    max_iterations: int = Field(ge=1, le=20)
    ecs_compatibility: Literal["disabled", "v1", "v8"] = "disabled"
    api_key: str | None = Field(default=None, max_length=512)  # None = keep, "" = clear
    extra_headers: dict[str, str] | None = None  # None = keep, {} = clear


@router.get("/ai")
async def ai_get(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    cfg = await get_setting(db, "ai")
    extra = await get_secret_setting(db, "ai_extra_headers")
    return {
        **cfg,
        "api_key_set": bool(await get_secret_setting(db, "ai_api_key")),
        "extra_header_names": sorted(json.loads(extra)) if extra else [],
    }


@router.put("/ai")
async def ai_put(
    body: AIConfigIn, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    data = body.model_dump(exclude={"api_key", "extra_headers"})
    await put_setting(db, "ai", data, principal.user.username)
    if body.api_key is not None:
        await put_secret_setting(db, "ai_api_key", body.api_key)
    if body.extra_headers is not None:
        await put_secret_setting(db, "ai_extra_headers", json.dumps(body.extra_headers) if body.extra_headers else None)
    await audit(
        db,
        "settings.ai_update",
        request=request,
        actor=principal.user,
        details={**data, "api_key_changed": body.api_key is not None},
    )
    await db.commit()
    return await ai_get(principal, db)


@router.post("/ai/test")
async def ai_test(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    cfg = await load_llm_config(db)
    try:
        reply = await chat(cfg, [{"role": "user", "content": "Reply with the single word: pong"}])
    except LLMError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "reply": reply[:200]}


class ModelsQuery(BaseModel):
    """Values currently typed in the form (may be unsaved). API key: None/"" = use the stored one."""

    provider: Literal["ollama", "openai"]
    base_url: str = Field(pattern=r"^https?://", max_length=512)
    api_key: str | None = Field(default=None, max_length=512)


@router.post("/ai/models")
async def ai_models(body: ModelsQuery, _: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    cfg = await load_llm_config(db)
    url = body.base_url.rstrip("/")
    if body.api_key:
        cfg.api_key = body.api_key
    elif url != cfg.base_url or body.provider != cfg.provider:
        # Never send the stored key / extra headers to an endpoint other than the saved one.
        cfg.api_key, cfg.extra_headers = None, {}
    cfg.provider, cfg.base_url = body.provider, url
    try:
        models = await list_models(cfg)
    except LLMError as exc:
        return {"ok": False, "error": str(exc), "models": []}
    return {"ok": True, "models": models}


# ---- Remote syslog -----------------------------------------------------------------------------
class SyslogConfigIn(BaseModel):
    enabled: bool
    host: str = Field(default="", max_length=253, pattern=r"^[A-Za-z0-9._:\-]*$")  # DNS name or IP, no scheme
    port: int = Field(ge=1, le=65535)
    protocol: Literal["udp", "tcp", "tls"]
    framing: Literal["octet_counting", "lf"] = "octet_counting"
    facility: Literal[tuple(syslog.FACILITIES)]  # type: ignore[valid-type]
    client_cert: str | None = Field(default=None, max_length=32_000)  # PEM. None = keep, "" = clear
    client_key: str | None = Field(default=None, max_length=32_000)

    @model_validator(mode="after")
    def _check(self):
        if self.enabled and not self.host:
            raise ValueError("a host is required to enable forwarding")
        return self


def _check_client_pair(cert_pem: str, key_pem: str) -> str:
    """Parse the PEM pair and make sure the key belongs to the certificate. Returns the subject."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "Invalid client certificate or key (unencrypted PEM expected)") from exc
    raw = serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(serialization.Encoding.DER, raw) != key.public_key().public_bytes(
        serialization.Encoding.DER, raw
    ):
        raise HTTPException(422, "The private key does not match the client certificate")
    return cert.subject.rfc4514_string()


@router.get("/syslog")
async def syslog_get(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    cert = await get_secret_setting(db, "syslog_client_cert")
    subject = expires = None
    if cert:
        parsed = x509.load_pem_x509_certificate(cert.encode())
        subject, expires = parsed.subject.rfc4514_string(), parsed.not_valid_after_utc
    return {
        **await get_setting(db, "syslog"),
        "client_cert_subject": subject,
        "client_cert_expires": expires,
        "status": syslog.status(),
    }


@router.put("/syslog")
async def syslog_put(
    body: SyslogConfigIn,
    request: Request,
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> dict:
    cert = body.client_cert if body.client_cert is not None else await get_secret_setting(db, "syslog_client_cert")
    key = body.client_key if body.client_key is not None else await get_secret_setting(db, "syslog_client_key")
    if bool(cert) != bool(key):
        raise HTTPException(422, "Provide both the client certificate and its private key, or neither")
    if cert and key:
        _check_client_pair(cert, key)
    data = body.model_dump(exclude={"client_cert", "client_key"})
    await put_setting(db, "syslog", data, principal.user.username)
    if body.client_cert is not None:
        await put_secret_setting(db, "syslog_client_cert", body.client_cert)
    if body.client_key is not None:
        await put_secret_setting(db, "syslog_client_key", body.client_key)
    await audit(
        db,
        "settings.syslog_update",
        request=request,
        actor=principal.user,
        details={**data, "client_cert_changed": body.client_cert is not None},
    )
    await db.commit()
    await apply_syslog_settings(db)
    return await syslog_get(principal, db)


@router.post("/syslog/test")
async def syslog_test(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    """Send one message with the saved settings (even when forwarding is disabled)."""
    target = await load_syslog_target(db)
    if target is None:
        return {"ok": False, "error": "No syslog server configured"}
    try:
        await run_in_threadpool(syslog.send_test, target)
    except (OSError, ValueError) as exc:  # ssl.SSLError is an OSError
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"[:300]}
    return {"ok": True, "unconfirmed": target.protocol == "udp"}


# ---- PKI injection ---------------------------------------------------------------------------
def _rebuild_bundle(pki: Path) -> None:
    pems = [p.read_text() for p in sorted(pki.glob("*.pem"))]
    bundle = pki / ".bundle.pem"
    if pems:
        bundle.write_text("\n".join(pems))
    else:
        bundle.unlink(missing_ok=True)


@router.get("/pki")
async def pki_list(_: Principal = Depends(admin_only)) -> list[dict]:
    pki = Path(get_settings().pki_dir)
    out = []
    for pem in sorted(pki.glob("*.pem")) if pki.is_dir() else []:
        try:
            certs = x509.load_pem_x509_certificates(pem.read_bytes())
        except ValueError:
            continue
        out.append(
            {
                "name": pem.name,
                "certificates": [
                    {"subject": c.subject.rfc4514_string(), "not_after": c.not_valid_after_utc} for c in certs
                ],
            }
        )
    return out


@router.post("/pki")
async def pki_upload(
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = await file.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise HTTPException(413, "PEM bundle too large")
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise HTTPException(422, "Not a valid PEM certificate bundle") from exc
    if any(b"PRIVATE KEY" in line for line in data.splitlines()):
        raise HTTPException(422, "Private keys are not accepted")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(file.filename or "ca").stem)[:64] + ".pem"
    pki = Path(get_settings().pki_dir)
    (pki / name).write_bytes(data)
    _rebuild_bundle(pki)
    await audit(
        db,
        "pki.upload",
        request=request,
        actor=principal.user,
        target=name,
        details={"subjects": [c.subject.rfc4514_string() for c in certs]},
    )
    await db.commit()
    return {"name": name, "count": len(certs)}


@router.delete("/pki/{name}")
async def pki_delete(
    name: str, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.pem", name) or name.startswith("."):
        raise HTTPException(400, "Invalid name")
    pki = Path(get_settings().pki_dir)
    (pki / name).unlink(missing_ok=True)
    _rebuild_bundle(pki)
    await audit(db, "pki.delete", request=request, actor=principal.user, target=name)
    await db.commit()
    return {"ok": True}


# ---- Audit trail -----------------------------------------------------------------------------
def _audit_query(action: str | None, actor: str | None, since: datetime | None):
    q = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        q = q.where(AuditLog.action.startswith(action))
    if actor:
        q = q.where(AuditLog.actor == actor)
    if since:
        q = q.where(AuditLog.ts >= since)
    return q


def _audit_out(a: AuditLog) -> dict:
    return {
        "id": a.id,
        "ts": a.ts,
        "actor": a.actor,
        "ip": a.ip,
        "action": a.action,
        "target": a.target,
        "outcome": a.outcome,
        "details": a.details,
    }


@router.get("/audit")
async def audit_list(
    action: str | None = Query(default=None, max_length=64),
    actor: str | None = Query(default=None, max_length=128),
    since: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    rows = (await db.execute(_audit_query(action, actor, since).limit(limit).offset(offset))).scalars()
    return [_audit_out(a) for a in rows]


@router.get("/audit/export")
async def audit_export(
    request: Request,
    action: str | None = Query(default=None, max_length=64),
    actor: str | None = Query(default=None, max_length=128),
    since: datetime | None = None,
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    rows = list((await db.execute(_audit_query(action, actor, since).limit(100_000))).scalars())
    await audit(
        db,
        "audit.export",
        request=request,
        actor=principal.user,
        details={"rows": len(rows), "action": action, "actor": actor},
    )
    await db.commit()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "ts", "actor", "ip", "action", "target", "outcome", "details"])
    for a in rows:
        # Neutralise spreadsheet formula injection.
        cells = [a.id, a.ts.isoformat(), a.actor, a.ip, a.action, a.target, a.outcome, json.dumps(a.details)]
        writer.writerow([("'" + c) if isinstance(c, str) and c[:1] in "=+-@" else c for c in cells])
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit.csv"'},
    )
