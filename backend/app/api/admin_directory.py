"""Administration of the OIDC and LDAPS directories (settings, secrets, connection tests)."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.deps import Principal, require_role
from app.db.models import Role
from app.db.session import get_db
from app.services import ldap_auth, oidc
from app.services.audit import audit
from app.services.directory import load_ldap, load_oidc, secret_is_set
from app.services.settings_store import get_setting, put_secret_setting, put_setting

router = APIRouter(prefix="/api/admin/directory", tags=["admin"])
admin_only = require_role(Role.ADMIN)
log = logging.getLogger(__name__)


class OidcIn(BaseModel):
    enabled: bool
    issuer: str = Field(default="", max_length=512, pattern=r"^(https?://\S+)?$")
    client_id: str = Field(default="", max_length=256)
    client_secret: str | None = Field(default=None, max_length=1024)  # None = keep, "" = clear
    scopes: str = Field(default="openid profile email", max_length=512, pattern=r"^openid( [\w:./-]+)*$")
    groups_claim: str = Field(default="groups", min_length=1, max_length=128)
    display_name: str = Field(default="SSO", min_length=1, max_length=64)

    @model_validator(mode="after")
    def _complete(self):
        if self.enabled and not (self.issuer and self.client_id):
            raise ValueError("issuer and client_id are required to enable OIDC")
        if self.issuer.startswith("http://") and get_settings().env != "development":
            raise ValueError("the issuer must use https:// (http:// is only accepted with LSX_ENV=development)")
        return self


class LdapIn(BaseModel):
    enabled: bool
    url: str = Field(default="", max_length=512, pattern=r"^(ldaps://\S+)?$")  # TLS is mandatory
    bind_dn: str = Field(default="", max_length=512)
    bind_password: str | None = Field(default=None, max_length=1024)  # None = keep, "" = clear
    user_base: str = Field(default="", max_length=512)
    user_filter: str = Field(
        default="(&(objectClass=person)(sAMAccountName={username}))", max_length=512, pattern=r"^\(.*\{username\}.*\)$"
    )
    group_attribute: str = Field(default="memberOf", min_length=1, max_length=64, pattern=r"^[A-Za-z][\w-]*$")

    @model_validator(mode="after")
    def _complete(self):
        if self.enabled and not (self.url and self.bind_dn and self.user_base):
            raise ValueError("url, bind_dn and user_base are required to enable LDAPS")
        return self


class LdapTestIn(BaseModel):
    username: str | None = Field(default=None, max_length=128)


async def _oidc_out(db: AsyncSession) -> dict:
    return {
        **await get_setting(db, "oidc"),
        "client_secret_set": await secret_is_set(db, "oidc_client_secret"),
        "redirect_uri": oidc.redirect_uri(),
    }


async def _ldap_out(db: AsyncSession) -> dict:
    return {**await get_setting(db, "ldap"), "bind_password_set": await secret_is_set(db, "ldap_bind_password")}


@router.get("")
async def directory_get(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    return {"oidc": await _oidc_out(db), "ldap": await _ldap_out(db)}


@router.put("/oidc")
async def oidc_put(
    body: OidcIn, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    data = body.model_dump(exclude={"client_secret"})
    data["issuer"] = data["issuer"].rstrip("/")
    await put_setting(db, "oidc", data, principal.user.username)
    if body.client_secret is not None:
        await put_secret_setting(db, "oidc_client_secret", body.client_secret)
    await audit(db, "settings.oidc_update", request=request, actor=principal.user,
                details={**data, "client_secret_changed": body.client_secret is not None})  # fmt: skip
    await db.commit()
    oidc.clear_discovery_cache()
    return await _oidc_out(db)


@router.put("/ldap")
async def ldap_put(
    body: LdapIn, request: Request, principal: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)
) -> dict:
    data = body.model_dump(exclude={"bind_password"})
    await put_setting(db, "ldap", data, principal.user.username)
    if body.bind_password is not None:
        await put_secret_setting(db, "ldap_bind_password", body.bind_password)
    await audit(db, "settings.ldap_update", request=request, actor=principal.user,
                details={**data, "bind_password_changed": body.bind_password is not None})  # fmt: skip
    await db.commit()
    return await _ldap_out(db)


@router.post("/oidc/test")
async def oidc_test(_: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    """Uses the saved settings, even when OIDC is disabled (validate before enabling)."""
    cfg = await load_oidc(db, require_enabled=False)
    if cfg is None:
        raise HTTPException(400, "Save an issuer and a client ID first")
    try:
        return {"ok": True, **await oidc.check(cfg)}
    except Exception as exc:  # noqa: BLE001 - reported to the administrator, not raised
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"[:400]}


@router.post("/ldap/test")
async def ldap_test(body: LdapTestIn, _: Principal = Depends(admin_only), db: AsyncSession = Depends(get_db)) -> dict:
    """TLS + service account bind, then optional user lookup (the user's password is never asked)."""
    cfg = await load_ldap(db, require_enabled=False)
    if cfg is None:
        raise HTTPException(400, "Save an ldaps:// URL first")
    try:
        return {"ok": True, **await ldap_auth.check(cfg, (body.username or "").strip() or None)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"[:400]}
