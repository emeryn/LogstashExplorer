"""Schema creation and first-boot seeding."""

import logging

from sqlalchemy import select, text

from app.core.secrets import require_secret
from app.core.security import hash_password
from app.db.models import AuditLog, AuthSource, Base, Role, User, UserStatus
from app.db.session import get_engine, sessionmaker

log = logging.getLogger(__name__)

MIGRATIONS = [
    "ALTER TABLE pipelines ADD COLUMN IF NOT EXISTS expected_output TEXT",
    "ALTER TABLE pipelines ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE pipelines ADD COLUMN IF NOT EXISTS updated_by VARCHAR(128)",
    "ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS scope VARCHAR(16) NOT NULL DEFAULT 'write'",
    "ALTER TABLE pipelines ADD COLUMN IF NOT EXISTS input_fields TEXT",
]


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        # Serialise schema creation across replicas.
        await conn.execute(text("SELECT pg_advisory_xact_lock(7340000)"))
        await conn.run_sync(Base.metadata.create_all)
        # Idempotent column additions for databases created by earlier versions (until Alembic).
        for stmt in MIGRATIONS:
            await conn.execute(text(stmt))

    async with sessionmaker()() as db:
        if (await db.execute(select(User.id).limit(1))).first():
            return
        db.add(
            User(
                username="admin",
                display_name="Administrator",
                role=Role.ADMIN,
                status=UserStatus.ACTIVE,
                auth_source=AuthSource.LOCAL,
                password_hash=hash_password(require_secret("admin_initial_password")),
                must_change_password=True,  # forced reset on first login
            )
        )
        db.add(AuditLog(actor="system", action="user.seed_admin", target="admin"))
        await db.commit()
        log.warning(
            "Default 'admin' account created with a generated one-time password "
            "(secret 'admin_initial_password'); a password change is forced at first login."
        )
