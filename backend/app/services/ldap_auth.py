"""LDAPS authentication (TLS mandatory, certificate validated) with group extraction."""

import ssl

from fastapi.concurrency import run_in_threadpool
from ldap3 import NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

from app.core.config import get_settings
from app.core.secrets import get_secret
from app.core.security import pki_bundle_path
from app.db.models import AuthSource
from app.services.provisioning import ExternalIdentity


def _server() -> Server:
    s = get_settings()
    if not s.ldap_url.lower().startswith("ldaps://"):
        raise RuntimeError("Only ldaps:// is allowed")
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_file=pki_bundle_path(),
    )
    return Server(s.ldap_url, use_ssl=True, tls=tls, get_info=NONE, connect_timeout=5)


def _cn(dn: str) -> str:
    try:
        for attr, value, _ in parse_dn(dn):
            if attr.lower() == "cn":
                return value
    except LDAPInvalidDnError:
        return dn  # not a DN (e.g. plain group name): map it as-is
    return dn


def _authenticate_sync(username: str, password: str) -> ExternalIdentity | None:
    if not username or not password:
        return None  # an empty password would be an anonymous bind
    s = get_settings()
    server = _server()
    attr = s.ldap_group_attribute
    with Connection(
        server, user=s.ldap_bind_dn, password=get_secret("ldap_bind_password") or "", auto_bind=True, read_only=True
    ) as svc:
        svc.search(
            s.ldap_user_base,
            s.ldap_user_filter.format(username=escape_filter_chars(username)),
            search_scope=SUBTREE,
            attributes=["mail", "displayName", "cn", attr, "entryUUID", "objectGUID"],
            size_limit=2,
        )
        if len(svc.entries) != 1:
            return None
        entry = svc.entries[0]
    user_dn = entry.entry_dn
    with Connection(server, user=user_dn, password=password, read_only=True) as conn:
        if not conn.bind():
            return None
    values = entry.entry_attributes_as_dict
    ext_id = (values.get("entryUUID") or values.get("objectGUID") or [user_dn])[0]
    groups = [str(g) for g in values.get(attr, [])]
    return ExternalIdentity(
        source=AuthSource.LDAP,
        external_id=str(ext_id),
        username=username,
        email=(values.get("mail") or [None])[0],
        display_name=(values.get("displayName") or values.get("cn") or [None])[0],
        groups=groups + [_cn(g) for g in groups],  # map on full DN or CN
    )


async def authenticate_ldap(username: str, password: str) -> ExternalIdentity | None:
    return await run_in_threadpool(_authenticate_sync, username, password)
