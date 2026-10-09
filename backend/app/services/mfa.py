"""MFA: TOTP (RFC 6238, anti-replay) and WebAuthn / FIDO2 passkeys."""

import json
import time
from datetime import timedelta

import pyotp
import webauthn
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import get_settings
from app.core.security import fingerprint
from app.db.models import AuthFlow, User, WebAuthnCredential, utcnow

ISSUER = "Logstash Explorer"


# ---- TOTP --------------------------------------------------------------------------------
def totp_provisioning(user: User, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=ISSUER)


def verify_totp(user: User, code: str, secret: str | None = None) -> bool:
    secret = secret or user.totp_secret
    if not secret or not code.isdigit():
        return False
    totp = pyotp.TOTP(secret)
    now = int(time.time())
    for drift in (-1, 0, 1):
        step = (now // totp.interval) + drift
        if step <= user.totp_last_step:
            continue  # anti-replay: each time step can be used only once
        if pyotp.utils.strings_equal(totp.at(step * totp.interval), code):
            user.totp_last_step = step
            return True
    return False


# ---- WebAuthn ----------------------------------------------------------------------------
def _origin() -> str:
    return get_settings().public_url.rstrip("/")


async def _store_challenge(db: AsyncSession, key: str, challenge: bytes) -> None:
    flow_id = fingerprint(key)
    await db.execute(delete(AuthFlow).where(AuthFlow.id == flow_id))
    db.add(
        AuthFlow(
            id=flow_id,
            kind="webauthn",
            data=json.dumps({"challenge": challenge.hex()}),
            expires_at=utcnow() + timedelta(minutes=5),
        )
    )
    await db.flush()


async def _pop_challenge(db: AsyncSession, key: str) -> bytes | None:
    flow = await db.get(AuthFlow, fingerprint(key))
    if flow is None:
        return None
    await db.delete(flow)
    await db.flush()
    if flow.expires_at <= utcnow():
        return None
    return bytes.fromhex(json.loads(flow.data)["challenge"])


async def registration_options(db: AsyncSession, user: User) -> str:
    s = get_settings()
    existing = (await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))).scalars()
    opts = webauthn.generate_registration_options(
        rp_id=s.webauthn_rp_id,
        rp_name=s.webauthn_rp_name,
        user_name=user.username,
        user_id=user.id.bytes,
        user_display_name=user.display_name or user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in existing],
    )
    await _store_challenge(db, f"reg:{user.id}", opts.challenge)
    return webauthn.options_to_json(opts)


async def verify_registration(db: AsyncSession, user: User, credential: dict, name: str) -> WebAuthnCredential:
    challenge = await _pop_challenge(db, f"reg:{user.id}")
    if challenge is None:
        raise ValueError("challenge expired")
    s = get_settings()
    verified = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=s.webauthn_rp_id,
        expected_origin=_origin(),
    )
    cred = WebAuthnCredential(
        user_id=user.id,
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        name=name[:128] or "Security key",
    )
    db.add(cred)
    await db.flush()
    return cred


async def authentication_options(db: AsyncSession, user: User) -> str | None:
    creds = list((await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))).scalars())
    if not creds:
        return None
    opts = webauthn.generate_authentication_options(
        rp_id=get_settings().webauthn_rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in creds],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    await _store_challenge(db, f"auth:{user.id}", opts.challenge)
    return webauthn.options_to_json(opts)


async def verify_authentication(db: AsyncSession, user: User, credential: dict) -> bool:
    challenge = await _pop_challenge(db, f"auth:{user.id}")
    if challenge is None:
        return False
    raw_id = webauthn.base64url_to_bytes(credential.get("rawId") or credential.get("id", ""))
    cred = (
        await db.execute(
            select(WebAuthnCredential).where(
                WebAuthnCredential.user_id == user.id, WebAuthnCredential.credential_id == raw_id
            )
        )
    ).scalar_one_or_none()
    if cred is None:
        return False
    s = get_settings()
    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=s.webauthn_rp_id,
            expected_origin=_origin(),
            credential_public_key=cred.public_key,
            credential_current_sign_count=cred.sign_count,
        )
    except Exception:  # noqa: BLE001 - any verification error is a failed MFA
        return False
    cred.sign_count = verified.new_sign_count
    return True


async def user_mfa_methods(db: AsyncSession, user: User) -> list[str]:
    methods = []
    if user.totp_enabled:
        methods.append("totp")
    has_key = (
        await db.execute(select(WebAuthnCredential.id).where(WebAuthnCredential.user_id == user.id).limit(1))
    ).first()
    if has_key:
        methods.append("webauthn")
    return methods
