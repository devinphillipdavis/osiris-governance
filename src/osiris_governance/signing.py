"""Ed25519 signing over canonical bytes. Pure: keys arrive and leave as PEM bytes, no file access.

Requires the optional `cryptography` package (`pip install osiris-governance[signing]`); nothing
else in the package imports it, and it is loaded only when a signing function is called.

Scope: a valid signature shows that the holder of the private key signed these exact bytes. It
says nothing about key custody (Cloud KMS, HSM); a closure signed with a local key must not
claim otherwise (see closure.py, SIGNER_TRUTH).

Fingerprint: "sha256:" + hex(SHA-256(raw 32-byte Ed25519 public key)).
Signature encoding: standard base64 of the 64-byte signature, one line.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Tuple

from .errors import SigningUnavailableError

SIGNATURE_ALGORITHM = "Ed25519"


def _crypto() -> Tuple[Any, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise SigningUnavailableError(
            "SIGNING_UNAVAILABLE: Ed25519 needs the 'cryptography' package; "
            "install osiris-governance[signing]."
        ) from exc
    return ed25519, serialization


def generate_private_key_pem() -> bytes:
    """A new Ed25519 private key as unencrypted PKCS8 PEM. Storing it safely is the caller's job."""
    ed25519, serialization = _crypto()
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_pem(private_key_pem: bytes) -> bytes:
    _, serialization = _crypto()
    return load_private_key_pem(private_key_pem).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key_pem(data: bytes) -> Any:
    ed25519, serialization = _crypto()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def load_public_key_pem(data: bytes) -> Any:
    ed25519, serialization = _crypto()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def public_key_fingerprint(public_key: Any) -> str:
    _, serialization = _crypto()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def sign_bytes(private_key: Any, data: bytes) -> bytes:
    return private_key.sign(data)


def verify_signature(public_key: Any, signature: bytes, data: bytes) -> bool:
    _crypto()
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


def encode_signature(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


def decode_signature(text: str) -> bytes:
    """Strict base64 decode of a detached signature; rejects anything but exactly 64 bytes."""
    try:
        signature = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"signature is not valid base64: {exc}") from exc
    if len(signature) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(signature)}")
    return signature
