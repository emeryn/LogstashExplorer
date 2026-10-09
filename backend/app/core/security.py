"""Password hashing (Argon2id), token primitives, password policy, PKI-aware TLS contexts."""

import hashlib
import secrets
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings

# OWASP / RFC 9106 second recommended profile (64 MiB, t=3, p=4).
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32, salt_len=16)
# Pre-computed hash used to equalise timing when a user does not exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))

_COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456789012",
    "azertyuiop",
    "qwertyuiop",
    "motdepasse",
    "administrator",
    "changeme1234",
    "welcome12345",
    "letmein12345",
    "admin1234567",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Constant-work verification: always runs one Argon2 computation."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except VerifyMismatchError, VerificationError, InvalidHashError:
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_policy_errors(password: str, username: str = "") -> list[str]:
    s = get_settings()
    errors = []
    if len(password) < s.password_min_length:
        errors.append(f"at least {s.password_min_length} characters required")
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if classes < 3:
        errors.append("use at least 3 of: lowercase, uppercase, digits, symbols")
    if username and username.lower() in password.lower():
        errors.append("must not contain the username")
    if password.lower() in _COMMON_PASSWORDS:
        errors.append("password is too common")
    return errors


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def fingerprint(token: str) -> str:
    """SHA3-256 fingerprint — what we store for sessions and API tokens."""
    return hashlib.sha3_256(token.encode()).hexdigest()


def is_public_origin(origin: str) -> bool:
    """True when an `Origin` header designates the application's public URL (CSRF / DNS rebinding)."""
    expected = urlsplit(get_settings().public_url)
    return origin.rstrip("/") == f"{expected.scheme}://{expected.netloc}"


def pki_bundle_path() -> str | None:
    bundle = Path(get_settings().pki_dir) / ".bundle.pem"
    return str(bundle) if bundle.is_file() else None


def tls_context() -> ssl.SSLContext:
    """System trust store + PEM certificates injected in the PKI directory. TLS >= 1.2."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    bundle = pki_bundle_path()
    if bundle:
        ctx.load_verify_locations(cafile=bundle)
    return ctx
