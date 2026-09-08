from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_validator_encryption_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    public = private.public_key()
    return (
        _b64(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        _b64(public.public_bytes(Encoding.Raw, PublicFormat.Raw)),
    )


@dataclass(frozen=True, slots=True)
class SealedReport:
    version: int
    submission_id: str
    report_nonce: str
    report_ciphertext: str
    report_ciphertext_hash: str
    report_commitment: str
    key_nonce: str
    wrapped_report_key: str
    ephemeral_public_key: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class OwnerKeyRelease:
    version: int
    submission_id: str
    report_ciphertext_hash: str
    owner_key_hash: str
    key_nonce: str
    wrapped_report_key: str
    ephemeral_public_key: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def encryption_public_key_hash(public_key: str) -> str:
    return "0x" + hashlib.sha256(_unb64(public_key)).hexdigest()


def seal_report(
    report: dict[str, Any], *, submission_id: str, validator_public_key: str
) -> SealedReport:
    if not submission_id.strip():
        raise ValueError("submission_id_required")
    plaintext = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report_key = AESGCM.generate_key(bit_length=256)
    report_nonce = os.urandom(12)
    aad = f"h1dr4-proofvault-report-v1\n{submission_id}".encode()
    ciphertext = AESGCM(report_key).encrypt(report_nonce, plaintext, aad)

    ephemeral = X25519PrivateKey.generate()
    validator = X25519PublicKey.from_public_bytes(_unb64(validator_public_key))
    wrapping_key = _derive_wrapping_key(
        ephemeral.exchange(validator),
        submission_id,
        purpose=b"h1dr4-proofvault-validator-key-wrap-v1",
    )
    key_nonce = os.urandom(12)
    wrapped_key = AESGCM(wrapping_key).encrypt(key_nonce, report_key, aad)
    return SealedReport(
        version=1,
        submission_id=submission_id,
        report_nonce=_b64(report_nonce),
        report_ciphertext=_b64(ciphertext),
        report_ciphertext_hash="0x" + hashlib.sha256(ciphertext).hexdigest(),
        report_commitment="0x" + hashlib.sha256(plaintext).hexdigest(),
        key_nonce=_b64(key_nonce),
        wrapped_report_key=_b64(wrapped_key),
        ephemeral_public_key=_b64(
            ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
    )


def open_report(
    report: SealedReport | dict[str, Any], *, validator_private_key: str
) -> dict[str, Any]:
    value = report if isinstance(report, SealedReport) else SealedReport(**report)
    if value.version != 1:
        raise ValueError("sealed_report_version_unsupported")
    ciphertext = _unb64(value.report_ciphertext)
    if value.report_ciphertext_hash != "0x" + hashlib.sha256(ciphertext).hexdigest():
        raise ValueError("sealed_report_ciphertext_hash_mismatch")
    private = X25519PrivateKey.from_private_bytes(_unb64(validator_private_key))
    ephemeral = X25519PublicKey.from_public_bytes(_unb64(value.ephemeral_public_key))
    wrapping_key = _derive_wrapping_key(
        private.exchange(ephemeral),
        value.submission_id,
        purpose=b"h1dr4-proofvault-validator-key-wrap-v1",
    )
    aad = f"h1dr4-proofvault-report-v1\n{value.submission_id}".encode()
    report_key = AESGCM(wrapping_key).decrypt(
        _unb64(value.key_nonce), _unb64(value.wrapped_report_key), aad
    )
    plaintext = AESGCM(report_key).decrypt(_unb64(value.report_nonce), ciphertext, aad)
    if value.report_commitment != "0x" + hashlib.sha256(plaintext).hexdigest():
        raise ValueError("sealed_report_commitment_mismatch")
    return json.loads(plaintext)


def rewrap_report_key_for_owner(
    report: SealedReport | dict[str, Any],
    *,
    validator_private_key: str,
    owner_public_key: str,
) -> OwnerKeyRelease:
    """Rewrap a report key after payout without publishing it or returning plaintext."""
    value = report if isinstance(report, SealedReport) else SealedReport(**report)
    if value.version != 1:
        raise ValueError("sealed_report_version_unsupported")
    validator_private = X25519PrivateKey.from_private_bytes(
        _unb64(validator_private_key)
    )
    validator_ephemeral = X25519PublicKey.from_public_bytes(
        _unb64(value.ephemeral_public_key)
    )
    validator_wrapping_key = _derive_wrapping_key(
        validator_private.exchange(validator_ephemeral),
        value.submission_id,
        purpose=b"h1dr4-proofvault-validator-key-wrap-v1",
    )
    report_aad = f"h1dr4-proofvault-report-v1\n{value.submission_id}".encode()
    report_key = AESGCM(validator_wrapping_key).decrypt(
        _unb64(value.key_nonce), _unb64(value.wrapped_report_key), report_aad
    )

    owner = X25519PublicKey.from_public_bytes(_unb64(owner_public_key))
    release_ephemeral = X25519PrivateKey.generate()
    owner_wrapping_key = _derive_wrapping_key(
        release_ephemeral.exchange(owner),
        value.submission_id,
        purpose=b"h1dr4-proofvault-owner-key-wrap-v1",
    )
    release_aad = _owner_release_aad(value.submission_id, value.report_ciphertext_hash)
    key_nonce = os.urandom(12)
    return OwnerKeyRelease(
        version=1,
        submission_id=value.submission_id,
        report_ciphertext_hash=value.report_ciphertext_hash,
        owner_key_hash=encryption_public_key_hash(owner_public_key),
        key_nonce=_b64(key_nonce),
        wrapped_report_key=_b64(
            AESGCM(owner_wrapping_key).encrypt(key_nonce, report_key, release_aad)
        ),
        ephemeral_public_key=_b64(
            release_ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
    )


def open_report_for_owner(
    report: SealedReport | dict[str, Any],
    release: OwnerKeyRelease | dict[str, Any],
    *,
    owner_private_key: str,
) -> dict[str, Any]:
    value = report if isinstance(report, SealedReport) else SealedReport(**report)
    key_release = (
        release if isinstance(release, OwnerKeyRelease) else OwnerKeyRelease(**release)
    )
    if value.version != 1 or key_release.version != 1:
        raise ValueError("sealed_report_version_unsupported")
    if (
        key_release.submission_id != value.submission_id
        or key_release.report_ciphertext_hash != value.report_ciphertext_hash
    ):
        raise ValueError("owner_release_report_mismatch")
    owner_private = X25519PrivateKey.from_private_bytes(_unb64(owner_private_key))
    owner_public = _b64(
        owner_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    if key_release.owner_key_hash != encryption_public_key_hash(owner_public):
        raise PermissionError("owner_release_key_mismatch")
    release_ephemeral = X25519PublicKey.from_public_bytes(
        _unb64(key_release.ephemeral_public_key)
    )
    owner_wrapping_key = _derive_wrapping_key(
        owner_private.exchange(release_ephemeral),
        value.submission_id,
        purpose=b"h1dr4-proofvault-owner-key-wrap-v1",
    )
    report_key = AESGCM(owner_wrapping_key).decrypt(
        _unb64(key_release.key_nonce),
        _unb64(key_release.wrapped_report_key),
        _owner_release_aad(value.submission_id, value.report_ciphertext_hash),
    )
    ciphertext = _unb64(value.report_ciphertext)
    if value.report_ciphertext_hash != "0x" + hashlib.sha256(ciphertext).hexdigest():
        raise ValueError("sealed_report_ciphertext_hash_mismatch")
    report_aad = f"h1dr4-proofvault-report-v1\n{value.submission_id}".encode()
    plaintext = AESGCM(report_key).decrypt(_unb64(value.report_nonce), ciphertext, report_aad)
    if value.report_commitment != "0x" + hashlib.sha256(plaintext).hexdigest():
        raise ValueError("sealed_report_commitment_mismatch")
    return json.loads(plaintext)


def _owner_release_aad(submission_id: str, report_ciphertext_hash: str) -> bytes:
    return (
        f"h1dr4-proofvault-owner-release-v1\n{submission_id}\n"
        f"{report_ciphertext_hash}"
    ).encode()


def _derive_wrapping_key(
    shared_secret: bytes, submission_id: str, *, purpose: bytes
) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(submission_id.encode()).digest(),
        info=purpose,
    ).derive(shared_secret)


@dataclass(frozen=True, slots=True)
class ValidationVerdict:
    submission_id: str
    valid: bool
    severity: str
    impact_commitment: str
    evidence_commitment: str
    validator_image_hash: str
    issued_at: str

    @classmethod
    def issue(
        cls,
        *,
        submission_id: str,
        valid: bool,
        severity: str,
        impact_commitment: str,
        evidence_commitment: str,
        validator_image_hash: str,
    ) -> ValidationVerdict:
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("validation_severity_invalid")
        return cls(
            submission_id=submission_id,
            valid=valid,
            severity=severity,
            impact_commitment=impact_commitment,
            evidence_commitment=evidence_commitment,
            validator_image_hash=validator_image_hash,
            issued_at=datetime.now(UTC).isoformat(),
        )

    def canonical_bytes(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


def sign_verdict(verdict: ValidationVerdict, key: Ed25519PrivateKey) -> dict[str, str]:
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "verdict_hash": "0x" + hashlib.sha256(verdict.canonical_bytes()).hexdigest(),
        "validator_public_key": _b64(public),
        "signature": _b64(key.sign(verdict.canonical_bytes())),
    }


def verify_verdict(verdict: ValidationVerdict, signature: dict[str, str]) -> bool:
    expected = "0x" + hashlib.sha256(verdict.canonical_bytes()).hexdigest()
    if signature.get("verdict_hash") != expected:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(signature["validator_public_key"])).verify(
            _unb64(signature["signature"]), verdict.canonical_bytes()
        )
    except (InvalidSignature, KeyError, ValueError):
        return False
    return True
