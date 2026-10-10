"""Revocable API tokens: shown once, stored as SHA3-256 fingerprints, mandatory expiration."""

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import fingerprint, new_token
from app.db.models import ApiToken, utcnow


async def create_token(
    db: AsyncSession, user_id: uuid.UUID, name: str, expires_in_days: int, scope: str = "write"
) -> tuple[ApiToken, str]:
    days = max(1, min(expires_in_days, get_settings().api_token_max_days))
    prefix = new_token(6)[:8]
    raw = f"lsx_{prefix}_{new_token(32)}"
    token = ApiToken(
        user_id=user_id,
        name=name[:128],
        prefix=prefix,
        fingerprint=fingerprint(raw),
        scope=scope,
        expires_at=utcnow() + timedelta(days=days),
    )
    db.add(token)
    await db.flush()
    return token, raw


async def list_tokens(db: AsyncSession, user_id: uuid.UUID) -> list[dict]:
    rows = (
        await db.execute(select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.created_at))
    ).scalars()
    return [token_out(t) for t in rows]


def token_out(t: ApiToken) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "prefix": t.prefix,
        "scope": t.scope,
        "created_at": t.created_at,
        "expires_at": t.expires_at,
        "revoked_at": t.revoked_at,
        "last_used_at": t.last_used_at,
    }


async def revoke_token(db: AsyncSession, user_id: uuid.UUID, token_id: uuid.UUID) -> ApiToken | None:
    token = await db.get(ApiToken, token_id)
    if token is None or token.user_id != user_id:
        return None
    if token.revoked_at is None:
        token.revoked_at = utcnow()
    return token
