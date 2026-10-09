"""Operational CLI.

python -m app.cli gen-secrets          # first-boot secret generation (idempotent)
python -m app.cli decrypt-backup IN OUT
python -m app.cli set-secret NAME < value   # e.g. ldap_bind_password, oidc_client_secret (stdin, never argv)
"""

import argparse
import os
import secrets
import string
import sys
from pathlib import Path

from app.core.config import get_settings
from app.core.crypto import HybridCipher, init_cipher
from app.core.secrets import SECRET_LOCATIONS, require_secret


def _password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "-_.!@#%"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def gen_secrets() -> None:
    root = Path(get_settings().secrets_dir)
    generated = {
        "db_password": _password(32),
        "admin_initial_password": _password(20),
        "runner_token": secrets.token_urlsafe(48),
        **HybridCipher.generate_secrets(),
    }
    for name, value in generated.items():
        path = root / SECRET_LOCATIONS[name] / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            continue
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "w") as fh:
            fh.write(value)
        if name == "db_password":
            os.chmod(path, 0o444)  # read by the postgres container (uid 70); volume only shared with db/backend
        print(f"generated secret {name}")
    print("secrets ready")


def decrypt_backup(src: str, dst: str) -> None:
    init_cipher(
        HybridCipher.from_secrets(
            require_secret("master_key"), require_secret("kem_x25519_sk"), require_secret("kem_mlkem768_seed")
        )
    )
    from app.core.crypto import get_cipher

    with open(src, "rb") as fin, open(dst, "wb") as fout:
        get_cipher().decrypt_stream(fin, fout, context="backup")
    print(f"decrypted to {dst} (restore with pg_restore)")


SETTABLE = ("ldap_bind_password", "oidc_client_secret")


def set_secret(name: str) -> None:
    if name not in SETTABLE:
        sys.exit(f"only {', '.join(SETTABLE)} can be set this way")
    value = sys.stdin.readline().rstrip("\r\n")
    if not value:
        sys.exit("empty value on stdin")
    path = Path(get_settings().secrets_dir) / SECRET_LOCATIONS[name] / name
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    with os.fdopen(fd, "w") as fh:
        fh.write(value)
    tmp.replace(path)
    print(f"secret {name} updated (restart the backend to apply)")


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-secrets")
    dec = sub.add_parser("decrypt-backup")
    dec.add_argument("src")
    dec.add_argument("dst")
    st = sub.add_parser("set-secret")
    st.add_argument("name")
    args = parser.parse_args()
    if args.cmd == "gen-secrets":
        gen_secrets()
    elif args.cmd == "decrypt-backup":
        decrypt_backup(args.src, args.dst)
    elif args.cmd == "set-secret":
        set_secret(args.name)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
