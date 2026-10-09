"""OpenID Connect — authorization code flow with PKCE (S256), state and nonce. No open redirects."""

import base64
import hashlib
import json
import secrets
import time
from datetime import timedelta
from urllib.parse import urlencode

import httpx
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.secrets import get_secret
from app.core.security import fingerprint, tls_context
from app.db.models import AuthFlow, AuthSource, utcnow
from app.services.provisioning import ExternalIdentity

_discovery_cache: dict[str, tuple[float, dict]] = {}


def safe_next(target: str | None) -> str:
    """Only same-origin relative paths are accepted (prevents open redirects)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target or "\n" in target:
        return "/"
    return target


def redirect_uri() -> str:
    return get_settings().public_url.rstrip("/") + "/api/auth/oidc/callback"


async def discovery() -> dict:
    issuer = get_settings().oidc_issuer.rstrip("/")
    cached = _discovery_cache.get(issuer)
    if cached and cached[0] > time.time():
        return cached[1]
    async with httpx.AsyncClient(verify=tls_context(), timeout=10) as client:
        resp = await client.get(f"{issuer}/.well-known/openid-configuration")
        resp.raise_for_status()
        doc = resp.json()
    if doc.get("issuer", "").rstrip("/") != issuer:
        raise ValueError("OIDC issuer mismatch")
    _discovery_cache[issuer] = (time.time() + 3600, doc)
    return doc


async def build_authorization_url(db: AsyncSession, next_path: str | None) -> str:
    s = get_settings()
    doc = await discovery()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    db.add(
        AuthFlow(
            id=fingerprint(state),
            kind="oidc",
            data=json.dumps({"nonce": nonce, "verifier": verifier, "next": safe_next(next_path)}),
            expires_at=utcnow() + timedelta(minutes=10),
        )
    )
    await db.flush()
    params = {
        "response_type": "code",
        "client_id": s.oidc_client_id,
        "redirect_uri": redirect_uri(),
        "scope": s.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{doc['authorization_endpoint']}?{urlencode(params)}"


async def handle_callback(db: AsyncSession, code: str, state: str) -> tuple[ExternalIdentity, str]:
    s = get_settings()
    flow = await db.get(AuthFlow, fingerprint(state))
    if flow is None or flow.kind != "oidc":
        raise ValueError("unknown or replayed state")
    await db.delete(flow)  # single use
    await db.flush()
    if flow.expires_at <= utcnow():
        raise ValueError("expired state")
    data = json.loads(flow.data)

    doc = await discovery()
    async with httpx.AsyncClient(verify=tls_context(), timeout=15) as client:
        resp = await client.post(
            doc["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri(),
                "code_verifier": data["verifier"],
                "client_id": s.oidc_client_id,
            },
            auth=(s.oidc_client_id, get_secret("oidc_client_secret") or ""),
        )
        resp.raise_for_status()
        tokens = resp.json()

    jwks = jwt.PyJWKClient(doc["jwks_uri"], ssl_context=tls_context())
    id_token = tokens["id_token"]
    signing_key = jwks.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "PS256", "ES256", "EdDSA"],
        audience=s.oidc_client_id,
        issuer=doc["issuer"],
        options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
    )
    if not secrets.compare_digest(claims["nonce"], data["nonce"]):
        raise ValueError("nonce mismatch")

    groups = claims.get(s.oidc_groups_claim) or []
    if isinstance(groups, str):
        groups = [groups]
    ident = ExternalIdentity(
        source=AuthSource.OIDC,
        external_id=claims["sub"],
        username=claims.get("preferred_username") or claims.get("email") or claims["sub"],
        email=claims.get("email"),
        display_name=claims.get("name"),
        groups=[str(g) for g in groups],
    )
    return ident, data["next"]
