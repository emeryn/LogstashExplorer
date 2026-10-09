import io

import pytest
from cryptography.exceptions import InvalidTag

from app.core.crypto import HybridCipher


@pytest.fixture
def cipher() -> HybridCipher:
    s = HybridCipher.generate_secrets()
    return HybridCipher.from_secrets(s["master_key"], s["kem_x25519_sk"], s["kem_mlkem768_seed"])


def test_field_roundtrip_and_randomised(cipher):
    a = cipher.encrypt("filter { grok {} }", "pipeline.config")
    b = cipher.encrypt("filter { grok {} }", "pipeline.config")
    assert a != b
    assert cipher.decrypt(a, "pipeline.config") == "filter { grok {} }"


def test_context_binding(cipher):
    token = cipher.encrypt("secret", "ai_api_key")
    with pytest.raises(InvalidTag):
        cipher.decrypt(token, "user.email")


def test_other_keys_cannot_decrypt(cipher):
    s = HybridCipher.generate_secrets()
    other = HybridCipher.from_secrets(s["master_key"], s["kem_x25519_sk"], s["kem_mlkem768_seed"])
    with pytest.raises(InvalidTag):
        other.decrypt(cipher.encrypt("x"))


@pytest.mark.parametrize("size", [0, 10, 64 * 1024, 64 * 1024 * 3 + 7])
def test_stream_roundtrip(cipher, size):
    data = bytes(range(256)) * (size // 256) + b"x" * (size % 256)
    enc = io.BytesIO()
    cipher.encrypt_stream(io.BytesIO(data), enc)
    out = io.BytesIO()
    cipher.decrypt_stream(io.BytesIO(enc.getvalue()), out)
    assert out.getvalue() == data


def test_stream_truncation_detected(cipher):
    enc = io.BytesIO()
    cipher.encrypt_stream(io.BytesIO(b"a" * (64 * 1024 * 2 + 1)), enc)
    raw = enc.getvalue()
    # Drop the final chunk: the previous chunk is now "last" but was not encrypted as such.
    last_len = int.from_bytes(raw[-(1 + 16 + 4) : -(1 + 16)], "big")
    assert last_len == 17
    with pytest.raises(InvalidTag):
        cipher.decrypt_stream(io.BytesIO(raw[: -(4 + 17)]), io.BytesIO())
