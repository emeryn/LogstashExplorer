"""Application-level encryption at rest.

Field format (v1), base64url-encoded:

    0x01 | x25519 ephemeral pub (32) | ML-KEM-768 ciphertext (1088) | nonce (12) | AES-256-GCM ct+tag

Content key = HKDF-SHA3-256( ss_x25519 || ss_mlkem768 || master_key , info = "lsx-field-v1|<context>" )

This is a hybrid (classical + post-quantum) KEM combiner: an attacker must break X25519 AND
ML-KEM-768 AND obtain the master key. The KEM private keys are kept separate from the master key
so they can later be moved to Vault/HSM (decrypt-only service) while writers only need public keys.

Backups use a chunked AES-256-GCM stream keyed from the master key (see `encrypt_stream`).
"""

import base64
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
X25519_PUB_LEN = 32
MLKEM768_CT_LEN = 1088
NONCE_LEN = 12
CHUNK = 64 * 1024
STREAM_MAGIC = b"LSXB1"


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _hkdf(material: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=length, salt=None, info=info).derive(material)


@dataclass
class HybridCipher:
    master_key: bytes
    x25519_sk: x25519.X25519PrivateKey
    mlkem_sk: mlkem.MLKEM768PrivateKey

    @classmethod
    def from_secrets(cls, master_key_b64: str, x25519_b64: str, mlkem_seed_b64: str) -> HybridCipher:
        master = _b64d(master_key_b64)
        if len(master) != 32:
            raise ValueError("master_key must be 32 bytes")
        return cls(
            master_key=master,
            x25519_sk=x25519.X25519PrivateKey.from_private_bytes(_b64d(x25519_b64)),
            mlkem_sk=mlkem.MLKEM768PrivateKey.from_seed_bytes(_b64d(mlkem_seed_b64)),
        )

    @staticmethod
    def generate_secrets() -> dict[str, str]:
        x_sk = x25519.X25519PrivateKey.generate()
        m_sk = mlkem.MLKEM768PrivateKey.generate()
        return {
            "master_key": _b64e(os.urandom(32)),
            "kem_x25519_sk": _b64e(
                x_sk.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ),
            "kem_mlkem768_seed": _b64e(m_sk.private_bytes_raw()),
        }

    def _content_key(self, ss_x: bytes, ss_m: bytes, context: str) -> bytes:
        return _hkdf(ss_x + ss_m + self.master_key, b"lsx-field-v1|" + context.encode())

    def encrypt(self, plaintext: str, context: str = "") -> str:
        eph = x25519.X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ss_x = eph.exchange(self.x25519_sk.public_key())
        ss_m, ct_m = self.mlkem_sk.public_key().encapsulate()
        key = self._content_key(ss_x, ss_m, context)
        nonce = os.urandom(NONCE_LEN)
        header = bytes([VERSION]) + eph_pub + ct_m
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), header)
        return _b64e(header + nonce + ct)

    def decrypt(self, token: str, context: str = "") -> str:
        raw = _b64d(token)
        if not raw or raw[0] != VERSION:
            raise ValueError("unsupported ciphertext version")
        o = 1
        eph_pub = raw[o : o + X25519_PUB_LEN]
        o += X25519_PUB_LEN
        ct_m = raw[o : o + MLKEM768_CT_LEN]
        o += MLKEM768_CT_LEN
        nonce = raw[o : o + NONCE_LEN]
        o += NONCE_LEN
        ss_x = self.x25519_sk.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
        ss_m = self.mlkem_sk.decapsulate(ct_m)
        key = self._content_key(ss_x, ss_m, context)
        return AESGCM(key).decrypt(nonce, raw[o:], raw[: 1 + X25519_PUB_LEN + MLKEM768_CT_LEN]).decode()

    # ---- Streaming encryption (backups) -------------------------------------------------
    def encrypt_stream(self, src: BinaryIO, dst: BinaryIO, context: str = "backup") -> None:
        salt = os.urandom(16)
        key = _hkdf(self.master_key + salt, b"lsx-stream-v1|" + context.encode())
        prefix = os.urandom(7)
        dst.write(STREAM_MAGIC + salt + prefix)
        aead = AESGCM(key)
        counter = 0
        chunk = src.read(CHUNK)
        while True:
            nxt = src.read(CHUNK)
            last = not nxt
            nonce = prefix + struct.pack(">I", counter) + (b"\x01" if last else b"\x00")
            ct = aead.encrypt(nonce, chunk, None)
            dst.write(struct.pack(">I", len(ct)) + ct)
            if last:
                break
            chunk, counter = nxt, counter + 1

    def decrypt_stream(self, src: BinaryIO, dst: BinaryIO, context: str = "backup") -> None:
        if src.read(len(STREAM_MAGIC)) != STREAM_MAGIC:
            raise ValueError("not an encrypted backup")
        salt, prefix = src.read(16), src.read(7)
        aead = AESGCM(_hkdf(self.master_key + salt, b"lsx-stream-v1|" + context.encode()))
        counter = 0
        hdr = src.read(4)
        while True:
            if len(hdr) < 4:
                raise ValueError("truncated backup")
            ct = src.read(struct.unpack(">I", hdr)[0])
            nxt = src.read(4)
            last = not nxt
            nonce = prefix + struct.pack(">I", counter) + (b"\x01" if last else b"\x00")
            # The "last" flag is authenticated in the nonce: truncation makes decryption fail.
            dst.write(aead.decrypt(nonce, ct, None))
            if last:
                return
            hdr, counter = nxt, counter + 1


_cipher: HybridCipher | None = None


def init_cipher(cipher: HybridCipher) -> None:
    global _cipher
    _cipher = cipher


def get_cipher() -> HybridCipher:
    if _cipher is None:
        raise RuntimeError("encryption not initialised")
    return _cipher
