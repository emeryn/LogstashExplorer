import logging
import time
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ChangePasswordIn, CodeIn, CredentialIn, LoginIn, user_out
from app.core.config import get_settings
from app.core.deps import Principal, get_principal_partial, get_principal_pw_change
from app.core.security import hash_password, password_policy_errors, verify_password
from app.db.models import AuthSource, User, UserStatus, utcnow
from app.db.session import get_db
from app.services import mfa, oidc
from app.services.audit import audit
from app.services.directory import load_ldap, load_oidc
from app.services.ldap_auth import authenticate_ldap
from app.services.local_auth import authenticate_local, equalise_timing
from app.services.provisioning import provision
from app.services.sessions import COOKIE_NAME, create_session, destroy_session, revoke_all_sessions

router = APIRouter(prefix="/api/auth", tags=["auth"])
log = logging.getLogger(__name__)
GENERIC_LOGIN_ERROR = "Invalid credentials or account unavailable"


async def _open_session(db: AsyncSession, request: Request, response: Response, user: User, method: str) -> dict:
    await destroy_session(db, None, request.cookies.get(COOKIE_NAME))  # prevent session fixation
    methods = await mfa.user_mfa_methods(db, user)
    await create_session(db, response, request, user.id, mfa_pending=bool(methods))
    await audit(db, "auth.login", request=request, actor=user, details={"method": method, "mfa": methods})
    await db.commit()
    return {"mfa_required": bool(methods), "mfa_methods": methods, "user": None if methods else user_out(user)}


@router.get("/providers")
async def providers(db: AsyncSession = Depends(get_db)) -> dict:
    oidc_cfg = await load_oidc(db)
    return {
        "local": True,
        "ldap": await load_ldap(db) is not None,
        "oidc": oidc_cfg is not None,
        "oidc_name": oidc_cfg.display_name if oidc_cfg else None,
    }


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    started = time.monotonic()
    result = await authenticate_local(db, body.username, body.password)
    if not result.ok:
        await audit(
            db,
            "auth.login",
            request=request,
            actor=result.user,
            actor_name=body.username[:128],
            outcome="failure",
            details={"method": "local", "reason": result.reason},
        )
        await db.commit()
        await equalise_timing(started)
        raise HTTPException(401, GENERIC_LOGIN_ERROR)
    out = await _open_session(db, request, response, result.user, "local")
    await equalise_timing(started)
    return out


@router.post("/ldap/login")
async def ldap_login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    ldap_cfg = await load_ldap(db)
    if ldap_cfg is None:
        raise HTTPException(404, "LDAP disabled")
    started = time.monotonic()
    try:
        ident = await authenticate_ldap(ldap_cfg, body.username, body.password)
    except Exception as exc:  # noqa: BLE001 - directory errors must not leak details
        log.error("LDAP error: %s", exc.__class__.__name__)
        ident = None
    if ident is None:
        await audit(
            db,
            "auth.login",
            request=request,
            actor_name=body.username[:128],
            outcome="failure",
            details={"method": "ldap"},
        )
        await db.commit()
        await equalise_timing(started)
        raise HTTPException(401, GENERIC_LOGIN_ERROR)
    user, created = await provision(db, ident)
    if created:
        await audit(
            db, "user.provision", request=request, actor=user, details={"source": "ldap", "status": user.status}
        )
    if user.status != UserStatus.ACTIVE:
        await audit(db, "auth.login", request=request, actor=user, outcome="failure", details={"reason": user.status})
        await db.commit()
        await equalise_timing(started)
        raise HTTPException(
            403,
            "Account pending administrator validation" if user.status == UserStatus.PENDING else GENERIC_LOGIN_ERROR,
        )
    out = await _open_session(db, request, response, user, "ldap")
    await equalise_timing(started)
    return out


@router.get("/oidc/login")
async def oidc_login(next: str | None = Query(default=None, max_length=512), db: AsyncSession = Depends(get_db)):
    oidc_cfg = await load_oidc(db)
    if oidc_cfg is None:
        raise HTTPException(404, "OIDC disabled")
    url = await oidc.build_authorization_url(db, oidc_cfg, next)
    await db.commit()
    return RedirectResponse(url, status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = Query(default=None, max_length=2048),
    state: str | None = Query(default=None, max_length=512),
    error: str | None = Query(default=None, max_length=256),
    db: AsyncSession = Depends(get_db),
):
    oidc_cfg = await load_oidc(db)
    if oidc_cfg is None:
        raise HTTPException(404, "OIDC disabled")
    if error or not code or not state:
        return RedirectResponse("/login?error=sso", status_code=302)
    try:
        ident, next_path = await oidc.handle_callback(db, oidc_cfg, code, state)
    except Exception as exc:  # noqa: BLE001
        log.warning("OIDC callback rejected: %s", exc)
        await audit(db, "auth.login", request=request, outcome="failure", details={"method": "oidc", "error": str(exc)})
        await db.commit()
        return RedirectResponse("/login?error=sso", status_code=302)
    user, created = await provision(db, ident)
    if created:
        await audit(
            db, "user.provision", request=request, actor=user, details={"source": "oidc", "status": user.status}
        )
    if user.status != UserStatus.ACTIVE:
        await audit(db, "auth.login", request=request, actor=user, outcome="failure", details={"reason": user.status})
        await db.commit()
        return RedirectResponse(f"/login?error={user.status.value}", status_code=302)
    redirect = RedirectResponse(oidc.safe_next(next_path), status_code=302)
    await _open_session(db, request, redirect, user, "oidc")
    return redirect


async def _finish_mfa(
    db: AsyncSession, request: Request, response: Response, principal: Principal, method: str
) -> dict:
    user = principal.user
    user.failed_attempts = 0
    # Rotate the session identifier once MFA is satisfied.
    await destroy_session(db, None, request.cookies.get(COOKIE_NAME))
    await create_session(db, response, request, user.id, mfa_pending=False)
    await audit(db, "auth.mfa", request=request, actor=user, details={"method": method})
    await db.commit()
    return {"user": user_out(user)}


async def _mfa_failure(db: AsyncSession, request: Request, principal: Principal, method: str) -> None:
    s = get_settings()
    user = principal.user
    user.failed_attempts += 1
    if user.failed_attempts >= s.lockout_threshold:
        user.locked_until = utcnow() + timedelta(minutes=s.lockout_minutes)
        user.failed_attempts = 0
        await revoke_all_sessions(db, user.id)
    await audit(db, "auth.mfa", request=request, actor=user, outcome="failure", details={"method": method})
    await db.commit()
    raise HTTPException(401, "Invalid verification code")


def _require_pending(principal: Principal) -> None:
    if not principal.session or not principal.session.mfa_pending:
        raise HTTPException(400, "No MFA challenge in progress")


@router.post("/mfa/totp")
async def mfa_totp(
    body: CodeIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal_partial),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_pending(principal)
    if not principal.user.totp_enabled or not mfa.verify_totp(principal.user, body.code):
        await _mfa_failure(db, request, principal, "totp")
    return await _finish_mfa(db, request, response, principal, "totp")


@router.post("/mfa/webauthn/options")
async def mfa_webauthn_options(
    principal: Principal = Depends(get_principal_partial), db: AsyncSession = Depends(get_db)
) -> Response:
    _require_pending(principal)
    options = await mfa.authentication_options(db, principal.user)
    await db.commit()
    if options is None:
        raise HTTPException(400, "No security key registered")
    return Response(options, media_type="application/json")


@router.post("/mfa/webauthn/verify")
async def mfa_webauthn_verify(
    body: CredentialIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal_partial),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_pending(principal)
    if not await mfa.verify_authentication(db, principal.user, body.credential):
        await _mfa_failure(db, request, principal, "webauthn")
    return await _finish_mfa(db, request, response, principal, "webauthn")


@router.get("/me")
async def me(principal: Principal = Depends(get_principal_partial), db: AsyncSession = Depends(get_db)) -> dict:
    pending = bool(principal.session and principal.session.mfa_pending)
    return {
        "mfa_pending": pending,
        "mfa_methods": await mfa.user_mfa_methods(db, principal.user) if pending else [],
        "user": user_out(principal.user),
    }


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    await destroy_session(db, response, request.cookies.get(COOKIE_NAME))
    await db.commit()
    return {"ok": True}


@router.post("/change-password")
async def change_password(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal_pw_change),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = principal.user
    if user.auth_source != AuthSource.LOCAL:
        raise HTTPException(400, "Password is managed by your identity provider")
    if not verify_password(body.current_password, user.password_hash):
        await audit(db, "auth.password_change", request=request, actor=user, outcome="failure")
        await db.commit()
        raise HTTPException(400, "Current password is incorrect")
    errors = password_policy_errors(body.new_password, user.username)
    if body.new_password == body.current_password:
        errors.append("new password must differ from the current one")
    if errors:
        raise HTTPException(422, "; ".join(errors))
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    # Invalidate every active session, then open a fresh one for the current browser.
    await revoke_all_sessions(db, user.id)
    await create_session(db, response, request, user.id)
    await audit(db, "auth.password_change", request=request, actor=user)
    await db.commit()
    return {"user": user_out(user)}
