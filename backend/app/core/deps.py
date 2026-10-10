"""Request dependencies: authentication (session cookie or API token) and role checks."""

from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import fingerprint
from app.db.models import ROLE_RANK, ApiToken, Role, Session, User, UserStatus, utcnow
from app.db.session import get_db
from app.services.sessions import COOKIE_NAME, load_session


@dataclass
class Principal:
    user: User
    session: Session | None = None
    token: ApiToken | None = None


async def _authenticate(request: Request, db: AsyncSession) -> Principal | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        raw = auth[7:].strip()
        token = (
            await db.execute(select(ApiToken).where(ApiToken.fingerprint == fingerprint(raw)))
        ).scalar_one_or_none()
        now = utcnow()
        if token is None or token.revoked_at is not None or token.expires_at <= now:
            return None
        user = await db.get(User, token.user_id)
        if user is None or user.status != UserStatus.ACTIVE:
            return None
        if token.last_used_at is None or now - token.last_used_at > timedelta(minutes=5):
            token.last_used_at = now
            await db.commit()
        return Principal(user=user, token=token)

    session = await load_session(db, request.cookies.get(COOKIE_NAME))
    if session is None:
        return None
    user = await db.get(User, session.user_id)
    if user is None or user.status != UserStatus.ACTIVE:
        return None
    now = utcnow()
    if now - session.last_seen_at > timedelta(seconds=60):
        session.last_seen_at = now
        await db.commit()
    return Principal(user=user, session=session)


# POST routes a read-only token may call: they compute or test, they never change stored data.
READ_ONLY_POSTS = {"/api/pipeline/run", "/api/pipeline/evtx", "/api/pipeline/laurel", "/api/parsers/detect", "/api/mcp"}


async def get_principal_partial(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    """Authenticated, but MFA may be pending and password change may be required."""
    principal = await _authenticate(request, db)
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    if principal.token is not None and principal.token.scope == "read":
        safe = request.method in ("GET", "HEAD") or (request.method == "POST" and request.url.path in READ_ONLY_POSTS)
        if not safe:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Read-only API token")
    return principal


async def get_principal_pw_change(principal: Principal = Depends(get_principal_partial)) -> Principal:
    """MFA completed; a pending password change is still allowed."""
    if principal.session and principal.session.mfa_pending:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA required")
    return principal


async def get_principal(principal: Principal = Depends(get_principal_pw_change)) -> Principal:
    if principal.user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password change required")
    return principal


def require_role(minimum: Role):
    async def checker(principal: Principal = Depends(get_principal)) -> Principal:
        if ROLE_RANK[principal.user.role] < ROLE_RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return principal

    return checker
