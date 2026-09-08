from __future__ import annotations

import json

import pytest
from cryptography.exceptions import InvalidTag

from h1dr4_attackgraph.workspace_sync import (
    WorkspaceEnvelope,
    WorkspaceEnvelopeCodec,
    generate_workspace_key,
)


def sealed_fixture():
    codec = WorkspaceEnvelopeCodec(generate_workspace_key())
    signer = codec.generate_signing_key()
    envelope = codec.seal(
        workspace_id="eng-owned",
        actor_id="agent-recon",
        payload={"kind": "finding", "secret": "fixture-token-123"},
        signing_key=signer,
        event_id="evt-fixture",
    )
    return codec, envelope


def test_workspace_envelope_round_trip_and_relay_sees_only_ciphertext():
    codec, envelope = sealed_fixture()
    serialized = json.dumps(envelope.to_dict(), sort_keys=True)

    assert "fixture-token-123" not in serialized
    assert codec.open(
        envelope,
        trusted_signers={envelope.actor_id: envelope.signing_public_key},
    ) == {"kind": "finding", "secret": "fixture-token-123"}


def test_workspace_envelope_rejects_wrong_workspace_key():
    _, envelope = sealed_fixture()
    wrong_codec = WorkspaceEnvelopeCodec(generate_workspace_key())

    with pytest.raises(InvalidTag):
        wrong_codec.open(envelope)


def test_workspace_envelope_rejects_untrusted_actor_key():
    codec, envelope = sealed_fixture()

    with pytest.raises(PermissionError, match="workspace_signer_not_trusted"):
        codec.open(envelope, trusted_signers={envelope.actor_id: "different-key"})


def test_workspace_envelope_rejects_ciphertext_tampering():
    codec, envelope = sealed_fixture()
    changed = envelope.to_dict()
    changed["ciphertext"] = changed["ciphertext"][:-1] + (
        "A" if changed["ciphertext"][-1] != "A" else "B"
    )

    with pytest.raises(ValueError, match="workspace_ciphertext_hash_mismatch"):
        codec.open(WorkspaceEnvelope(**changed))
