"""Audit trail: every critical action is persisted (DB) and emitted on the `audit` logger (syslog)."""

import logging
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, User

log = logging.getLogger("audit")


def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    # The front proxy is the only ingress; it overwrites X-Real-IP with the peer address.
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


async def audit(
    db: AsyncSession,
    action: str,
    *,
    request: Request | None = None,
    actor: User | None = None,
    actor_name: str | None = None,
    target: str | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor=actor.username if actor else actor_name,
        ip=client_ip(request),
        action=action,
        target=target,
        outcome=outcome,
        details=details or {},
    )
    db.add(entry)
    await db.flush()
    level = logging.INFO if outcome == "success" else logging.WARNING
    log.log(
        level,
        "%s %s",
        action,
        outcome,
        extra={"ctx": {"actor": entry.actor, "ip": entry.ip, "target": target, "details": entry.details}},
    )
