"""Scheduled hygiene and backups. Each job takes a PostgreSQL advisory lock so that it runs
once even with several backend replicas."""

import asyncio
import logging
import os
import subprocess  # nosec B404 # only used with a fixed argv
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import and_, delete, or_, text, update

from app.core.config import get_settings
from app.core.crypto import get_cipher
from app.core.secrets import require_secret
from app.db.models import ApiToken, AuditLog, AuthFlow, AuthSource, Role, Session, User, UserStatus, utcnow
from app.db.session import sessionmaker

log = logging.getLogger(__name__)
LOCK_HYGIENE = 7_340_001
LOCK_BACKUP = 7_340_002
PG_DUMP = "/usr/bin/pg_dump"


async def account_hygiene() -> None:
    s = get_settings()
    async with sessionmaker()() as db:
        if not (await db.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": LOCK_HYGIENE})).scalar():
            return
        now = utcnow()
        cutoff = now - timedelta(days=s.inactive_account_days)
        # Disable inactive human accounts (never the last remaining admins: they are excluded by role).
        res = await db.execute(
            update(User)
            .where(
                User.status == UserStatus.ACTIVE,
                User.auth_source != AuthSource.SERVICE,
                User.role != Role.ADMIN,
                or_(User.last_login_at < cutoff, and_(User.last_login_at.is_(None), User.created_at < cutoff)),
            )
            .values(status=UserStatus.DISABLED)
            .returning(User.username)
        )
        disabled = [r[0] for r in res]
        await db.execute(delete(Session).where(Session.expires_at <= now))
        await db.execute(delete(AuthFlow).where(AuthFlow.expires_at <= now))
        # Purge tokens expired/revoked for more than 30 days (kept meanwhile for audit).
        old = now - timedelta(days=30)
        await db.execute(delete(ApiToken).where(or_(ApiToken.expires_at < old, ApiToken.revoked_at < old)))
        for username in disabled:
            db.add(
                AuditLog(actor="system", action="user.auto_disable", target=username, details={"reason": "inactive"})
            )
        await db.commit()
        if disabled:
            log.warning("disabled %d inactive accounts", len(disabled), extra={"ctx": {"users": disabled}})


def _pg_dump_encrypted(target: Path) -> None:
    s = get_settings()
    env = {"PGPASSWORD": require_secret("db_password"), "PATH": os.environ.get("PATH", "/usr/bin")}
    with tempfile.TemporaryFile() as raw:
        subprocess.run(  # noqa: S603 # nosec B603 # fixed argv, no shell
            [PG_DUMP, "-h", s.db_host, "-p", str(s.db_port), "-U", s.db_user, "-d", s.db_name, "-Fc"],
            stdout=raw,
            env=env,
            check=True,
            timeout=1800,
        )
        raw.seek(0)
        tmp = target.with_suffix(".partial")
        with tmp.open("wb") as out:
            get_cipher().encrypt_stream(raw, out, context="backup")
        os.chmod(tmp, 0o600)
        tmp.rename(target)


async def database_backup() -> None:
    s = get_settings()
    async with sessionmaker()() as db:
        if not (await db.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": LOCK_BACKUP})).scalar():
            return
        backup_dir = Path(s.backup_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)
        target = backup_dir / f"lsx-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.dump.enc"
        try:
            await asyncio.to_thread(_pg_dump_encrypted, target)
        except (subprocess.SubprocessError, OSError) as exc:
            log.error("database backup failed: %s", exc)
            db.add(AuditLog(actor="system", action="backup.run", outcome="failure", details={"error": str(exc)}))
            await db.commit()
            return
        cutoff = datetime.now(UTC) - timedelta(days=s.backup_retention_days)
        for old in backup_dir.glob("lsx-*.dump.enc"):
            if datetime.fromtimestamp(old.stat().st_mtime, UTC) < cutoff:
                old.unlink(missing_ok=True)
        db.add(AuditLog(actor="system", action="backup.run", target=target.name))
        await db.commit()
        log.info("encrypted backup written", extra={"ctx": {"file": target.name}})


def start_scheduler() -> AsyncIOScheduler:
    s = get_settings()
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(account_hygiene, IntervalTrigger(hours=1), id="hygiene", next_run_time=datetime.now(UTC))
    scheduler.add_job(database_backup, CronTrigger(hour=s.backup_hour_utc, minute=0), id="backup")
    scheduler.start()
    return scheduler
