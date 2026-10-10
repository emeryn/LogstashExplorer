"""LDAPS authentication (TLS mandatory, certificate validated) with group extraction."""

import ssl

from fastapi.concurrency import run_in_threadpool
from ldap3 import NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

from app.core.security import pki_bundle_path
from app.db.models import AuthSource
from app.services.directory import LdapConfig
from app.services.provisioning import ExternalIdentity


def _server(cfg: LdapConfig) -> Server:
    if not cfg.url.lower().startswith("ldaps://"):
        raise RuntimeError("Only ldaps:// is allowed")
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_file=pki_bundle_path(),
    )
    return Server(cfg.url, use_ssl=True, tls=tls, get_info=NONE, connect_timeout=5)


def _cn(dn: str) -> str:
    try:
        for attr, value, _ in parse_dn(dn):
            if attr.lower() == "cn":
                return value
    except LDAPInvalidDnError:
        return dn  # not a DN (e.g. plain group name): map it as-is
    return dn


def _service_connection(cfg: LdapConfig, server: Server) -> Connection:
    return Connection(server, user=cfg.bind_dn, password=cfg.bind_password, auto_bind=True, read_only=True)


def _find_user(cfg: LdapConfig, svc: Connection, username: str):
    svc.search(
        cfg.user_base,
        cfg.user_filter.format(username=escape_filter_chars(username)),
        search_scope=SUBTREE,
        attributes=["mail", "displayName", "cn", cfg.group_attribute, "entryUUID", "objectGUID"],
        size_limit=2,
    )
    return svc.entries[0] if len(svc.entries) == 1 else None


def _identity(cfg: LdapConfig, entry, username: str) -> ExternalIdentity:
    values = entry.entry_attributes_as_dict
    ext_id = (values.get("entryUUID") or values.get("objectGUID") or [entry.entry_dn])[0]
    groups = [str(g) for g in values.get(cfg.group_attribute, [])]
    return ExternalIdentity(
        source=AuthSource.LDAP,
        external_id=str(ext_id),
        username=username,
        email=(values.get("mail") or [None])[0],
        display_name=(values.get("displayName") or values.get("cn") or [None])[0],
        groups=groups + [_cn(g) for g in groups],  # map on full DN or CN
    )


def _authenticate_sync(cfg: LdapConfig, username: str, password: str) -> ExternalIdentity | None:
    if not username or not password:
        return None  # an empty password would be an anonymous bind
    server = _server(cfg)
    with _service_connection(cfg, server) as svc:
        entry = _find_user(cfg, svc, username)
    if entry is None:
        return None
    with Connection(server, user=entry.entry_dn, password=password, read_only=True) as conn:
        if not conn.bind():
            return None
    return _identity(cfg, entry, username)


def _check_sync(cfg: LdapConfig, username: str | None) -> dict:
    server = _server(cfg)
    with _service_connection(cfg, server) as svc:
        result: dict = {"bind": "ok"}
        if username:
            entry = _find_user(cfg, svc, username)
            if entry is None:
                result["user"] = None
            else:
                ident = _identity(cfg, entry, username)
                result["user"] = {
                    "dn": entry.entry_dn,
                    "display_name": ident.display_name,
                    "email_found": bool(ident.email),
                    "groups": sorted({_cn(g) for g in ident.groups})[:50],
                }
    return result


async def authenticate_ldap(cfg: LdapConfig, username: str, password: str) -> ExternalIdentity | None:
    return await run_in_threadpool(_authenticate_sync, cfg, username, password)


async def check(cfg: LdapConfig, username: str | None = None) -> dict:
    """Admin connection test: TLS + service bind, and optionally look a user up (no user password)."""
    return await run_in_threadpool(_check_sync, cfg, username)
