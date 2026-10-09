"""Server-side sessions. The cookie holds a random token; the DB stores only its SHA3-256 fingerprint."""

import uuid
from datetime import timedelta

from fastapi import Request, Response
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import fingerprint, new_token
from app.db.models import Session, utcnow
from app.services.audit import client_ip

COOKIE_NAME = "lsx_session"


async def create_session(
    db: AsyncSession, response: Response, request: Request, user_id: uuid.UUID, mfa_pending: bool = False
) -> Session:
    s = get_settings()
    token = new_token(32)
    now = utcnow()
    session = Session(
        id=fingerprint(token),
        user_id=user_id,
        mfa_pending=mfa_pending,
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(minutes=s.session_absolute_minutes),
    )
    db.add(session)
    await db.flush()
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
        max_age=s.session_absolute_minutes * 60,
    )
    return session


async def load_session(db: AsyncSession, token: str | None) -> Session | None:
    if not token:
        return None
    session = await db.get(Session, fingerprint(token))
    if session is None:
        return None
    now = utcnow()
    idle = timedelta(minutes=get_settings().session_idle_minutes)
    if session.expires_at <= now or session.last_seen_at + idle <= now:
        await db.delete(session)
        await db.commit()
        return None
    return session


async def destroy_session(db: AsyncSession, response: Response | None, token: str | None) -> None:
    """Delete the server-side session; clear the cookie unless a new one is about to be set."""
    if token:
        await db.execute(delete(Session).where(Session.id == fingerprint(token)))
    if response is not None:
        response.delete_cookie(
            COOKIE_NAME, path="/", secure=get_settings().cookie_secure, httponly=True, samesite="lax"
        )


async def revoke_all_sessions(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(delete(Session).where(Session.user_id == user_id))
