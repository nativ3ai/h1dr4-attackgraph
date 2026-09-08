from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_workspace_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


@dataclass(frozen=True, slots=True)
class WorkspaceEnvelope:
    version: int
    workspace_id: str
    event_id: str
    actor_id: str
    created_at: str
    nonce: str
    ciphertext: str
    ciphertext_hash: str
    signing_public_key: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class WorkspaceEnvelopeCodec:
    """End-to-end encrypted event envelopes for an untrusted collaboration relay."""

    def __init__(self, workspace_key: bytes) -> None:
        if len(workspace_key) != 32:
            raise ValueError("workspace_key_must_be_32_bytes")
        self.workspace_key = workspace_key

    @staticmethod
    def generate_signing_key() -> Ed25519PrivateKey:
        return Ed25519PrivateKey.generate()

    def seal(
        self,
        *,
        workspace_id: str,
        actor_id: str,
        payload: dict[str, Any],
        signing_key: Ed25519PrivateKey,
        event_id: str = "",
    ) -> WorkspaceEnvelope:
        event_id = event_id or f"evt_{uuid.uuid4().hex}"
        created_at = datetime.now(UTC).isoformat()
        aad = self._aad(workspace_id, event_id, actor_id, created_at)
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = AESGCM(self.workspace_key).encrypt(nonce, plaintext, aad)
        digest = hashlib.sha256(ciphertext).hexdigest()
        signed = aad + bytes.fromhex(digest)
        public_key = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return WorkspaceEnvelope(
            version=1,
            workspace_id=workspace_id,
            event_id=event_id,
            actor_id=actor_id,
            created_at=created_at,
            nonce=_b64(nonce),
            ciphertext=_b64(ciphertext),
            ciphertext_hash="0x" + digest,
            signing_public_key=_b64(public_key),
            signature=_b64(signing_key.sign(signed)),
        )

    def open(
        self,
        envelope: WorkspaceEnvelope | dict[str, Any],
        *,
        trusted_signers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        value = (
            envelope
            if isinstance(envelope, WorkspaceEnvelope)
            else WorkspaceEnvelope(**envelope)
        )
        if value.version != 1:
            raise ValueError("workspace_envelope_version_unsupported")
        if trusted_signers is not None:
            expected = trusted_signers.get(value.actor_id)
            if not expected or expected != value.signing_public_key:
                raise PermissionError("workspace_signer_not_trusted")
        ciphertext = _unb64(value.ciphertext)
        digest = hashlib.sha256(ciphertext).hexdigest()
        if value.ciphertext_hash != "0x" + digest:
            raise ValueError("workspace_ciphertext_hash_mismatch")
        aad = self._aad(value.workspace_id, value.event_id, value.actor_id, value.created_at)
        try:
            Ed25519PublicKey.from_public_bytes(_unb64(value.signing_public_key)).verify(
                _unb64(value.signature), aad + bytes.fromhex(digest)
            )
        except InvalidSignature as exc:
            raise ValueError("workspace_signature_invalid") from exc
        plaintext = AESGCM(self.workspace_key).decrypt(_unb64(value.nonce), ciphertext, aad)
        return json.loads(plaintext)

    @staticmethod
    def _aad(workspace_id: str, event_id: str, actor_id: str, created_at: str) -> bytes:
        return f"h1dr4-workspace-v1\n{workspace_id}\n{event_id}\n{actor_id}\n{created_at}".encode()
