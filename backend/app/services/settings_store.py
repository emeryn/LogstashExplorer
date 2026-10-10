"""Runtime settings stored in DB (editable from the admin interface)."""

import copy
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import logging as lsx_logging
from app.core import syslog
from app.db.models import AppSetting, SecretSetting

DEFAULTS: dict[str, dict[str, Any]] = {
    "logging": {"masking_enabled": True, "level": "INFO"},
    "provisioning": {"auto_provisioning": False, "default_role": "user"},
    "oidc": {
        "enabled": False,
        "issuer": "",
        "client_id": "",
        "scopes": "openid profile email",
        "groups_claim": "groups",
        "display_name": "SSO",
    },
    "ldap": {
        "enabled": False,
        "url": "",
        "bind_dn": "",
        "user_base": "",
        "user_filter": "(&(objectClass=person)(sAMAccountName={username}))",
        "group_attribute": "memberOf",
    },
    "mcp": {"enabled": True},
    "syslog": {
        "enabled": False,
        "host": "",
        "port": 6514,
        "protocol": "tls",  # udp | tcp | tls
        "framing": "octet_counting",  # octet_counting | lf (TCP/TLS)
        "facility": "local0",
    },
    "ai": {
        "provider": "ollama",  # ollama | openai
        "base_url": "http://host.docker.internal:11434",
        "model": "llama3.1:8b",
        "temperature": 0.1,
        "timeout_s": 180,
        "max_iterations": 6,
        "ecs_compatibility": "disabled",
    },
}


async def get_setting(db: AsyncSession, key: str) -> dict[str, Any]:
    row = await db.get(AppSetting, key)
    value = copy.deepcopy(DEFAULTS.get(key, {}))
    if row and isinstance(row.value, dict):
        value.update(row.value)
    return value


async def put_setting(db: AsyncSession, key: str, value: dict[str, Any], actor: str) -> dict[str, Any]:
    allowed = set(DEFAULTS.get(key, {}))
    clean = {k: v for k, v in value.items() if k in allowed}
    row = await db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key, value=clean, updated_by=actor)
        db.add(row)
    else:
        merged = dict(row.value or {})
        merged.update(clean)
        row.value = merged
        row.updated_by = actor
    await db.flush()
    if key == "logging":
        await apply_logging_settings(db)
    return await get_setting(db, key)


async def get_secret_setting(db: AsyncSession, key: str) -> str | None:
    row = await db.get(SecretSetting, key)
    return row.value if row else None


async def put_secret_setting(db: AsyncSession, key: str, value: str | None) -> None:
    row = await db.get(SecretSetting, key)
    if value in (None, ""):
        if row:
            await db.delete(row)
        return
    if row is None:
        db.add(SecretSetting(key=key, value=value))
    else:
        row.value = value


async def apply_logging_settings(db: AsyncSession) -> None:
    cfg = await get_setting(db, "logging")
    lsx_logging.masking_state.enabled = bool(cfg["masking_enabled"])
    lsx_logging.set_level(cfg["level"])


async def load_syslog_target(db: AsyncSession) -> syslog.SyslogTarget | None:
    cfg = await get_setting(db, "syslog")
    if not cfg["host"]:
        return None
    return syslog.SyslogTarget(
        host=cfg["host"],
        port=int(cfg["port"]),
        protocol=cfg["protocol"],
        framing=cfg["framing"],
        facility=cfg["facility"],
        client_cert=await get_secret_setting(db, "syslog_client_cert"),
        client_key=await get_secret_setting(db, "syslog_client_key"),
    )


async def apply_syslog_settings(db: AsyncSession) -> None:
    """Start, restart or stop log forwarding according to the stored settings."""
    enabled = (await get_setting(db, "syslog"))["enabled"]
    target = await load_syslog_target(db) if enabled else None
    try:
        syslog.configure(target, [lsx_logging.PiiMaskingFilter()])
    except (OSError, ValueError) as exc:  # e.g. unreadable client certificate
        logging.getLogger(__name__).error("syslog forwarding not started: %s", exc.__class__.__name__)
