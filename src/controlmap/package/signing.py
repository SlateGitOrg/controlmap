"""Ed25519 signatures over the package manifest.

The manifest lists the SHA-256 of every file, so one signature over ``manifest.json`` covers
the whole package. Keys are stored as PEM (PKCS#8 private, SubjectPublicKeyInfo public). The
public key should reach the auditor through a separate channel; a key shipped inside the
package proves integrity only, not origin.
"""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..canonical import sha256_bytes
from ..errors import PackageError

ALGORITHM = "ed25519"


def generate_keypair(private_path: Path, public_path: Path) -> str:
    """Write a new key pair (private key mode 0600). Returns the public-key fingerprint."""
    if private_path.exists() or public_path.exists():
        raise PackageError("refusing to overwrite an existing key file")
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.touch(mode=0o600)
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem(key.public_key()))
    return fingerprint(key.public_key())


def public_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(key: Ed25519PublicKey) -> str:
    """SHA-256 over the raw 32-byte public key, hex-encoded."""
    return sha256_bytes(raw_public(key))


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise PackageError(f"cannot load private key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise PackageError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise PackageError(f"cannot load public key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise PackageError(f"{path} is not an Ed25519 public key")
    return key


def sign(key: Ed25519PrivateKey, payload: bytes) -> dict[str, str]:
    public = key.public_key()
    return {
        "algorithm": ALGORITHM,
        "signed_file": "manifest.json",
        "public_key": base64.b64encode(raw_public(public)).decode("ascii"),
        "public_key_fingerprint": fingerprint(public),
        "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
    }


def verify_signature(document: dict[str, object], payload: bytes) -> Ed25519PublicKey:
    """Check a signature document against ``payload``; return the embedded public key."""
    if document.get("algorithm") != ALGORITHM:
        raise PackageError(f"unsupported signature algorithm {document.get('algorithm')!r}")
    try:
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(str(document["public_key"]), validate=True)
        )
        signature = base64.b64decode(str(document["signature"]), validate=True)
    except (KeyError, ValueError) as exc:
        raise PackageError(f"malformed signature document: {exc}") from exc
    try:
        public.verify(signature, payload)
    except InvalidSignature as exc:
        raise PackageError("manifest signature does not verify") from exc
    return public
