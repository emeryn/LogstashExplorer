from app.core.logging import mask_pii
from app.core.security import fingerprint, hash_password, password_policy_errors, verify_password
from app.services.oidc import safe_next


def test_argon2id_roundtrip():
    h = hash_password("Correct-Horse-9")
    assert h.startswith("$argon2id$")
    assert verify_password("Correct-Horse-9", h)
    assert not verify_password("wrong", h)
    assert not verify_password("anything", None)  # unknown user still burns one hash


def test_password_policy():
    assert password_policy_errors("short")
    assert password_policy_errors("alice-Password-1", "alice")
    assert not password_policy_errors("Tr0ub4dor&3-xyz", "alice")


def test_sha3_fingerprint():
    assert len(fingerprint("abc")) == 64
    assert fingerprint("abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"


def test_open_redirect_protection():
    assert safe_next("/workspace?x=1") == "/workspace?x=1"
    for bad in ("https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)", None, ""):
        assert safe_next(bad) == "/"


def test_pii_masking():
    masked = mask_pii("user jane.doe@example.com called +33 6 12 34 56 78 from 10.0.0.1")
    assert "[EMAIL]" in masked and "[PHONE]" in masked
    assert "jane.doe" not in masked
    assert "10.0.0.1" in masked  # IPs are kept for the audit trail
