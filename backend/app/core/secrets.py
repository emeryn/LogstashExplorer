"""Secret providers.

- file  : one file per secret (default; generated on first start by `python -m app.cli gen-secrets`).
- env   : `LSX_SECRET_<NAME>` variables — local development only.
- vault : HashiCorp Vault KV v2, token read from a file (e.g. Vault Agent sidecar).
"""

import json
import logging
import os
import ssl
import urllib.request
from functools import lru_cache
from pathlib import Path

from app.core.config import get_settings

log = logging.getLogger(__name__)

# Where each secret lives inside the file backend (separate volumes = least privilege).
_DB, _APP, _RUNNER = "db", "app", "runner"
SECRET_LOCATIONS = {
    "db_password": _DB,
    "master_key": _APP,
    "kem_x25519_sk": _APP,
    "kem_mlkem768_seed": _APP,
    "admin_initial_password": _APP,
    "oidc_client_secret": _APP,
    "ldap_bind_password": _APP,
    "runner_token": _RUNNER,
}


class SecretNotFound(KeyError):
    pass


def _from_file(name: str) -> str:
    s = get_settings()
    sub = SECRET_LOCATIONS.get(name, _APP)
    path = Path(s.secrets_dir) / sub / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise SecretNotFound(name) from exc


def _from_env(name: str) -> str:
    value = os.environ.get(f"LSX_SECRET_{name.upper()}")
    if value is None:
        raise SecretNotFound(name)
    return value


@lru_cache
def _vault_data() -> dict[str, str]:
    s = get_settings()
    if not s.vault_addr.startswith("https://"):
        raise RuntimeError("Vault address must use https://")
    token = Path(s.vault_token_file).read_text(encoding="utf-8").strip()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_kv_mount}/data/{s.vault_kv_path}"
    req = urllib.request.Request(url, headers={"X-Vault-Token": token})  # noqa: S310 - https enforced above
    ctx = ssl.create_default_context()
    pki = Path(s.pki_dir)
    if pki.is_dir():
        for pem in sorted(pki.glob("*.pem")):
            ctx.load_verify_locations(cafile=str(pem))
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:  # noqa: S310 # nosec B310
        return json.load(resp)["data"]["data"]


def _from_vault(name: str) -> str:
    data = _vault_data()
    if name not in data:
        raise SecretNotFound(name)
    return str(data[name])


def get_secret(name: str, default: str | None = None) -> str | None:
    backend = get_settings().secrets_backend
    reader = {"file": _from_file, "env": _from_env, "vault": _from_vault}[backend]
    try:
        return reader(name)
    except SecretNotFound:
        if default is not None:
            return default
        log.debug("secret %s not available from %s backend", name, backend)
        return None


def require_secret(name: str) -> str:
    value = get_secret(name)
    if not value:
        raise RuntimeError(f"Required secret '{name}' is missing")
    return value
