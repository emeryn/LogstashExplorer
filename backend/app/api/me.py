"""Self-service profile: sessions, TOTP, WebAuthn keys, personal API tokens."""

import uuid

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.mcp import TOOLS
from app.api.schemas import CodeIn, CredentialIn, TokenIn
from app.core.config import get_settings
from app.core.deps import Principal, get_principal
from app.db.models import ROLE_RANK, Session, WebAuthnCredential
from app.db.session import get_db
from app.services import mfa
from app.services.audit import audit
from app.services.settings_store import get_setting
from app.services.tokens import create_token, list_tokens, revoke_token, token_out

router = APIRouter(prefix="/api/me", tags=["profile"])


@router.get("/sessions")
async def sessions(principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = (
        await db.execute(select(Session).where(Session.user_id == principal.user.id, Session.mfa_pending.is_(False)))
    ).scalars()
    current = principal.session.id if principal.session else None
    return [
        {
            "ip": r.ip,
            "user_agent": r.user_agent,
            "created_at": r.created_at,
            "last_seen_at": r.last_seen_at,
            "current": r.id == current,
        }
        for r in rows
    ]


@router.delete("/sessions")
async def revoke_other_sessions(
    request: Request, principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)
) -> dict:
    stmt = delete(Session).where(Session.user_id == principal.user.id)
    if principal.session:
        stmt = stmt.where(Session.id != principal.session.id)
    await db.execute(stmt)
    await audit(db, "session.revoke_all", request=request, actor=principal.user)
    await db.commit()
    return {"ok": True}


# ---- TOTP ----------------------------------------------------------------------------------
@router.post("/totp/setup")
async def totp_setup(principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)) -> dict:
    user = principal.user
    if user.totp_enabled:
        raise HTTPException(400, "TOTP already enabled")
    secret = pyotp.random_base32()
    user.totp_secret = secret
    await db.commit()
    return {"secret": secret, "otpauth_uri": mfa.totp_provisioning(user, secret)}


@router.post("/totp/enable")
async def totp_enable(
    body: CodeIn, request: Request, principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)
) -> dict:
    user = principal.user
    if user.totp_enabled or not user.totp_secret:
        raise HTTPException(400, "Run setup first")
    if not mfa.verify_totp(user, body.code):
        raise HTTPException(400, "Invalid code")
    user.totp_enabled = True
    await audit(db, "mfa.totp_enable", request=request, actor=user)
    await db.commit()
    return {"ok": True}


@router.post("/totp/disable")
async def totp_disable(
    body: CodeIn, request: Request, principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)
) -> dict:
    user = principal.user
    if not user.totp_enabled or not mfa.verify_totp(user, body.code):
        raise HTTPException(400, "Invalid code")
    user.totp_enabled = False
    user.totp_secret = None
    await audit(db, "mfa.totp_disable", request=request, actor=user)
    await db.commit()
    return {"ok": True}


# ---- WebAuthn ------------------------------------------------------------------------------
@router.get("/webauthn")
async def webauthn_list(
    principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    rows = (
        await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == principal.user.id))
    ).scalars()
    return [{"id": str(r.id), "name": r.name, "created_at": r.created_at} for r in rows]


@router.post("/webauthn/register/options")
async def webauthn_register_options(
    principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)
) -> Response:
    options = await mfa.registration_options(db, principal.user)
    await db.commit()
    return Response(options, media_type="application/json")


@router.post("/webauthn/register/verify")
async def webauthn_register_verify(
    body: CredentialIn,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        cred = await mfa.verify_registration(db, principal.user, body.credential, body.name)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise HTTPException(400, f"Registration failed: {exc.__class__.__name__}") from exc
    await audit(db, "mfa.webauthn_register", request=request, actor=principal.user, target=cred.name)
    await db.commit()
    return {"id": str(cred.id), "name": cred.name}


@router.delete("/webauthn/{cred_id}")
async def webauthn_delete(
    cred_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: AsyncSession = Depends(get_db),
) -> dict:
    cred = await db.get(WebAuthnCredential, cred_id)
    if cred is None or cred.user_id != principal.user.id:
        raise HTTPException(404, "Not found")
    await db.delete(cred)
    await audit(db, "mfa.webauthn_delete", request=request, actor=principal.user, target=cred.name)
    await db.commit()
    return {"ok": True}


# ---- MCP -------------------------------------------------------------------------------------
@router.get("/mcp")
async def mcp_info(principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)) -> dict:
    """What an MCP client connected with one of my tokens gets (role-dependent tool list)."""
    rank = ROLE_RANK[principal.user.role]
    return {
        "enabled": (await get_setting(db, "mcp"))["enabled"],
        "url": get_settings().public_url.rstrip("/") + "/api/mcp",
        "tools": [
            {"name": t.name, "description": t.description, "read_only": t.read_only}
            for t in TOOLS.values()
            if rank >= ROLE_RANK[t.min_role]
        ],
    }


# ---- API tokens ----------------------------------------------------------------------------
@router.get("/tokens")
async def tokens(principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)) -> list[dict]:
    return await list_tokens(db, principal.user.id)


@router.post("/tokens")
async def token_create(
    body: TokenIn, request: Request, principal: Principal = Depends(get_principal), db: AsyncSession = Depends(get_db)
) -> dict:
    if principal.token is not None:
        raise HTTPException(403, "API tokens cannot mint new tokens")
    token, raw = await create_token(db, principal.user.id, body.name, body.expires_in_days, body.scope)
    await audit(
        db,
        "token.create",
        request=request,
        actor=principal.user,
        target=token.name,
        details={"expires_at": token.expires_at.isoformat(), "scope": token.scope},
    )
    await db.commit()
    return {**token_out(token), "token": raw}  # displayed once


@router.delete("/tokens/{token_id}")
async def token_revoke(
    token_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: AsyncSession = Depends(get_db),
) -> dict:
    token = await revoke_token(db, principal.user.id, token_id)
    if token is None:
        raise HTTPException(404, "Not found")
    await audit(db, "token.revoke", request=request, actor=principal.user, target=token.name)
    await db.commit()
    return {"ok": True}
