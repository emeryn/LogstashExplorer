"""Local username/password authentication with lockout and timing-attack mitigation."""

import asyncio
import time
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import hash_password, needs_rehash, verify_password
from app.db.models import AuthSource, User, UserStatus, utcnow


class LoginResult:
    def __init__(self, user: User | None, reason: str):
        self.user = user
        self.reason = reason  # ok | invalid | locked | pending | disabled

    @property
    def ok(self) -> bool:
        return self.reason == "ok"


async def equalise_timing(started: float) -> None:
    """Pad the response so success/failure/unknown user all take the same minimum time."""
    remaining = get_settings().login_min_duration_ms / 1000 - (time.monotonic() - started)
    if remaining > 0:
        await asyncio.sleep(remaining)


async def authenticate_local(db: AsyncSession, username: str, password: str) -> LoginResult:
    s = get_settings()
    user = (
        await db.execute(
            select(User).where(
                func.lower(User.username) == username.strip().lower(), User.auth_source == AuthSource.LOCAL
            )
        )
    ).scalar_one_or_none()

    # Always run exactly one Argon2 verification (dummy hash when the user is unknown).
    valid = verify_password(password, user.password_hash if user else None)
    if user is None:
        return LoginResult(None, "invalid")

    now = utcnow()
    if user.locked_until and user.locked_until > now:
        return LoginResult(user, "locked")
    if not valid:
        user.failed_attempts += 1
        if user.failed_attempts >= s.lockout_threshold:
            user.locked_until = now + timedelta(minutes=s.lockout_minutes)
            user.failed_attempts = 0
            await db.flush()
            return LoginResult(user, "locked")
        await db.flush()
        return LoginResult(user, "invalid")
    if user.status == UserStatus.PENDING:
        return LoginResult(user, "pending")
    if user.status == UserStatus.DISABLED:
        return LoginResult(user, "disabled")

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    await db.flush()
    return LoginResult(user, "ok")
