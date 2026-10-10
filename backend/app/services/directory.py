"""OIDC and LDAPS settings, editable from the admin interface.

Non-secret values live in `app_settings` (keys "oidc" / "ldap"); the OIDC client secret and the LDAP
bind password are encrypted in `secret_settings`. When a secret is not stored in the database, the
secret manager (file / env / Vault) is used instead, so production deployments can keep it in Vault.
LSX_OIDC_* / LSX_LDAP_* environment variables only seed the database on first boot.
"""

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.secrets import get_secret
from app.db.models import AppSetting
from app.services.settings_store import get_secret_setting, get_setting, put_setting


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str
    scopes: str
    groups_claim: str
    display_name: str


@dataclass(frozen=True)
class LdapConfig:
    url: str
    bind_dn: str
    bind_password: str
    user_base: str
    user_filter: str
    group_attribute: str


async def _secret(db: AsyncSession, name: str) -> str:
    return await get_secret_setting(db, name) or get_secret(name) or ""


async def load_oidc(db: AsyncSession, *, require_enabled: bool = True) -> OidcConfig | None:
    cfg = await get_setting(db, "oidc")
    if (require_enabled and not cfg["enabled"]) or not cfg["issuer"] or not cfg["client_id"]:
        return None
    return OidcConfig(
        issuer=cfg["issuer"].rstrip("/"),
        client_id=cfg["client_id"],
        client_secret=await _secret(db, "oidc_client_secret"),
        scopes=cfg["scopes"],
        groups_claim=cfg["groups_claim"],
        display_name=cfg["display_name"],
    )


async def load_ldap(db: AsyncSession, *, require_enabled: bool = True) -> LdapConfig | None:
    cfg = await get_setting(db, "ldap")
    if (require_enabled and not cfg["enabled"]) or not cfg["url"]:
        return None
    return LdapConfig(
        url=cfg["url"],
        bind_dn=cfg["bind_dn"],
        bind_password=await _secret(db, "ldap_bind_password"),
        user_base=cfg["user_base"],
        user_filter=cfg["user_filter"],
        group_attribute=cfg["group_attribute"],
    )


async def secret_is_set(db: AsyncSession, name: str) -> bool:
    return bool(await _secret(db, name))


async def seed_from_environment(db: AsyncSession) -> None:
    """First boot only: import LSX_OIDC_* / LSX_LDAP_* into the database (never overwrites admin edits)."""
    s = get_settings()
    if s.oidc_enabled and await db.get(AppSetting, "oidc") is None:
        await put_setting(
            db,
            "oidc",
            {
                "enabled": True,
                "issuer": s.oidc_issuer,
                "client_id": s.oidc_client_id,
                "scopes": s.oidc_scopes,
                "groups_claim": s.oidc_groups_claim,
                "display_name": s.oidc_display_name,
            },
            "environment",
        )
    if s.ldap_enabled and await db.get(AppSetting, "ldap") is None:
        await put_setting(
            db,
            "ldap",
            {
                "enabled": True,
                "url": s.ldap_url,
                "bind_dn": s.ldap_bind_dn,
                "user_base": s.ldap_user_base,
                "user_filter": s.ldap_user_filter,
                "group_attribute": s.ldap_group_attribute,
            },
            "environment",
        )
    await db.commit()
