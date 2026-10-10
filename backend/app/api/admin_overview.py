"""Administration dashboard, user detail sheet and approval of pending (SSO / LDAPS) accounts."""

import uuid
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import user_out
from app.core import syslog
from app.core.config import get_settings
from app.core.deps import Principal, require_role
from app.db.models import (
    ApiToken,
    AuditLog,
    Pipeline,
    PipelineShare,
    Role,
    Session,
    User,
    UserGroup,
    UserStatus,
    WebAuthnCredential,
    utcnow,
)
from app.db.session import get_db
from app.services.audit import audit
from app.services.directory import load_ldap, load_oidc
from app.services.sessions import revoke_all_sessions
from app.services.settings_store import get_setting
from app.services.tokens import list_tokens

router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_only = require_role(Role.ADMIN)
CERT_WARNING_DAYS = 30


class ApproveIn(BaseModel):
    role: Role = Role.USER


async def _count(db: AsyncSession, stmt) -> int:
    return (await db.execute(stmt)).scalar_one()


def _expiring_certificates() -> list[dict]:
    pki = Path(get_settings().pki_dir)
    limit = utcnow() + timedelta(days=CERT_WARNING_DAYS)
    out = []
    for pem in sorted(pki.glob("*.pem")) if pki.is_dir() else []:
        try:
            certs = x509.load_pem_x509_certificates(pem.read_bytes())
        except ValueError:
            continue
        out += [
            {"file": pem.name, "subject": c.subject.rfc4514_string(), "not_after": c.not_valid_after_utc}
            for c in certs
            if c.not_valid_after_utc <= limit
        ]
    return out


def _last_backup() -> dict | None:
    files = sorted(Path(get_settings().backup_dir).glob("lsx-*.dump.enc"), key=lambda f: f.stat().st_mtime)
    if not files:
        return None
    last = files[-1]
    return {"file": last.name, "size": last.stat().st_size, "count": len(files)}


@router.get("/overview")
async def overview(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    now = utcnow()
    since = now - timedelta(hours=24)
    by_status = dict((await db.execute(select(User.status, func.count()).group_by(User.status))).all())
    by_role = dict(
        (
            await db.execute(
                select(User.role, func.count()).where(User.status == UserStatus.ACTIVE).group_by(User.role)
            )
        ).all()
    )
    pending = (
        (await db.execute(select(User).where(User.status == UserStatus.PENDING).order_by(User.created_at).limit(50)))
        .scalars()
        .all()
    )
    groups: dict[uuid.UUID, list[str]] = {}
    if pending:
        rows = await db.execute(
            select(UserGroup.user_id, UserGroup.group).where(UserGroup.user_id.in_([u.id for u in pending]))
        )
        for uid, group in rows:
            groups.setdefault(uid, []).append(group)

    def audit_count(action: str, outcome: str | None = None):
        stmt = select(func.count()).select_from(AuditLog).where(AuditLog.action == action, AuditLog.ts >= since)
        return stmt.where(AuditLog.outcome == outcome) if outcome else stmt

    active_humans = select(User.id).where(User.status == UserStatus.ACTIVE, User.auth_source != "service")
    with_mfa = await _count(
        db,
        select(func.count()).where(
            User.id.in_(active_humans),
            or_(User.totp_enabled.is_(True), User.id.in_(select(WebAuthnCredential.user_id))),
        ),
    )
    failures = (
        await db.execute(select(AuditLog).where(AuditLog.outcome != "success").order_by(AuditLog.ts.desc()).limit(10))
    ).scalars()
    ai = await get_setting(db, "ai")
    oidc_cfg, ldap_cfg = await load_oidc(db), await load_ldap(db)
    return {
        "users": {
            "by_status": {s.value: by_status.get(s, 0) for s in UserStatus},
            "by_role": {r.value: by_role.get(r, 0) for r in Role},
            "locked": await _count(db, select(func.count()).where(User.locked_until > now)),
            "humans_active": await _count(db, select(func.count()).where(User.id.in_(active_humans))),
            "humans_with_mfa": with_mfa,
            "pending": [{**user_out(u), "groups": sorted(groups.get(u.id, []))[:20]} for u in pending],
        },
        "activity_24h": {
            "logins": await _count(db, audit_count("auth.login", "success")),
            "failed_logins": await _count(db, audit_count("auth.login", "failure")),
            "agent_runs": await _count(db, audit_count("agent.run")),
            "mcp_calls": await _count(db, audit_count("mcp.tool_call")),
        },
        "totals": {
            "projects": await _count(db, select(func.count()).select_from(Pipeline)),
            "active_sessions": await _count(
                db, select(func.count()).where(Session.expires_at > now, Session.mfa_pending.is_(False))
            ),
            "active_tokens": await _count(
                db, select(func.count()).where(ApiToken.revoked_at.is_(None), ApiToken.expires_at > now)
            ),
        },
        "integrations": {
            "llm": {"provider": ai["provider"], "model": ai["model"], "host": urlsplit(ai["base_url"]).hostname},
            "oidc": {"enabled": oidc_cfg is not None, "name": oidc_cfg.display_name if oidc_cfg else None},
            "ldap": {"enabled": ldap_cfg is not None, "host": urlsplit(ldap_cfg.url).hostname if ldap_cfg else None},
            "syslog": {**syslog.status(), "enabled": (await get_setting(db, "syslog"))["enabled"]},
            "mcp": {"enabled": (await get_setting(db, "mcp"))["enabled"]},
            "backup": _last_backup(),
            "expiring_certificates": _expiring_certificates(),
        },
        "recent_failures": [
            {"ts": a.ts, "actor": a.actor, "ip": a.ip, "action": a.action, "target": a.target} for a in failures
        ],
    }


@router.get("/users/{user_id}/detail")
async def user_detail(user_id: uuid.UUID, _: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    now = utcnow()
    sessions = (
        await db.execute(
            select(Session)
            .where(Session.user_id == user_id, Session.expires_at > now, Session.mfa_pending.is_(False))
            .order_by(Session.last_seen_at.desc())
        )
    ).scalars()
    groups = await db.execute(
        select(UserGroup.source, UserGroup.group, UserGroup.synced_at).where(UserGroup.user_id == user_id)
    )
    keys = await _count(db, select(func.count()).where(WebAuthnCredential.user_id == user_id))
    events = (
        await db.execute(
            select(AuditLog)
            .where(or_(AuditLog.actor_id == user_id, AuditLog.target == user.username))
            .order_by(AuditLog.ts.desc())
            .limit(25)
        )
    ).scalars()
    return {
        "user": user_out(user),
        "mfa": {"totp": user.totp_enabled, "security_keys": keys},
        "groups": [{"source": s, "group": g, "synced_at": t} for s, g, t in groups],
        "sessions": [
            {"ip": s.ip, "user_agent": s.user_agent, "created_at": s.created_at, "last_seen_at": s.last_seen_at}
            for s in sessions
        ],
        "tokens": [t for t in await list_tokens(db, user_id) if not t["revoked_at"] and t["expires_at"] > now],
        "projects": {
            "owned": await _count(db, select(func.count()).where(Pipeline.owner_id == user_id)),
            "shared_with": await _count(db, select(func.count()).where(PipelineShare.user_id == user_id)),
        },
        "audit": [
            {"ts": a.ts, "action": a.action, "outcome": a.outcome, "ip": a.ip, "actor": a.actor, "target": a.target}
            for a in events
        ],
    }


@router.post("/users/{user_id}/approve")
async def user_approve(
    user_id: uuid.UUID,
    body: ApproveIn,
    request: Request,
    principal: Principal = Depends(admin_only),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await db.get(User, user_id)
    if user is None or user.status != UserStatus.PENDING:
        raise HTTPException(409, "Only pending accounts can be approved")
    user.status, user.role = UserStatus.ACTIVE, body.role
    await audit(db, "user.approve", request=request, actor=principal.user, target=user.username,
                details={"role": body.role.value})  # fmt: skip
    await db.commit()
    return user_out(user)


@router.post("/users/{user_id}/reject")
async def user_reject(
    user_id: uuid.UUID, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    """Disable rather than delete: a deleted account would be re-created as pending at its next login."""
    user = await db.get(User, user_id)
    if user is None or user.status != UserStatus.PENDING:
        raise HTTPException(409, "Only pending accounts can be rejected")
    user.status = UserStatus.DISABLED
    await audit(db, "user.reject", request=request, actor=principal.user, target=user.username)
    await db.commit()
    return user_out(user)


@router.post("/users/{user_id}/revoke-sessions")
async def user_revoke_sessions(
    user_id: uuid.UUID, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    await revoke_all_sessions(db, user.id)
    await audit(db, "session.revoke_all", request=request, actor=principal.user, target=user.username)
    await db.commit()
    return {"ok": True}
