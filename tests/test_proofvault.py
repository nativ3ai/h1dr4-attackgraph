from __future__ import annotations

import json
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from h1dr4_attackgraph.proofvault import (
    ValidationVerdict,
    encryption_public_key_hash,
    generate_validator_encryption_keypair,
    open_report,
    open_report_for_owner,
    rewrap_report_key_for_owner,
    seal_report,
    sign_verdict,
    verify_verdict,
)


def test_report_is_private_to_validator_and_commitments_survive_transport():
    private_key, public_key = generate_validator_encryption_keypair()
    plaintext = {
        "target": "0x0000000000000000000000000000000000000042",
        "finding": "fixture reentrancy path",
        "reproduction": ["forge test --match-test test_fixture"],
    }

    sealed = seal_report(plaintext, submission_id="submission-7", validator_public_key=public_key)
    serialized = json.dumps(sealed.to_dict(), sort_keys=True)

    assert "reentrancy" not in serialized
    assert "forge test" not in serialized
    assert sealed.report_ciphertext_hash.startswith("0x")
    assert sealed.report_commitment.startswith("0x")
    assert open_report(sealed, validator_private_key=private_key) == plaintext


def test_report_cannot_be_opened_by_another_validator():
    _, public_key = generate_validator_encryption_keypair()
    wrong_private_key, _ = generate_validator_encryption_keypair()
    sealed = seal_report(
        {"finding": "fixture only"},
        submission_id="submission-8",
        validator_public_key=public_key,
    )

    with pytest.raises(InvalidTag):
        open_report(sealed, validator_private_key=wrong_private_key)


def test_paid_key_release_is_bound_to_the_registered_owner_key():
    validator_private, validator_public = generate_validator_encryption_keypair()
    owner_private, owner_public = generate_validator_encryption_keypair()
    wrong_owner_private, _ = generate_validator_encryption_keypair()
    plaintext = {"finding": "fixture storage collision", "proof": "forge-test-42"}
    sealed = seal_report(
        plaintext,
        submission_id="submission-owner-release",
        validator_public_key=validator_public,
    )

    release = rewrap_report_key_for_owner(
        sealed,
        validator_private_key=validator_private,
        owner_public_key=owner_public,
    )

    assert release.owner_key_hash == encryption_public_key_hash(owner_public)
    assert "storage collision" not in json.dumps(release.to_dict())
    assert open_report_for_owner(
        sealed, release, owner_private_key=owner_private
    ) == plaintext
    with pytest.raises(PermissionError, match="owner_release_key_mismatch"):
        open_report_for_owner(
            sealed,
            release,
            owner_private_key=wrong_owner_private,
        )


def test_signed_verdict_detects_changed_outcome():
    signing_key = Ed25519PrivateKey.generate()
    verdict = ValidationVerdict.issue(
        submission_id="submission-9",
        valid=True,
        severity="critical",
        impact_commitment="0ximpact",
        evidence_commitment="0xevidence",
        validator_image_hash="sha256:fixture-image",
    )
    signature = sign_verdict(verdict, signing_key)

    assert verify_verdict(verdict, signature)
    assert not verify_verdict(replace(verdict, valid=False), signature)


def test_verdict_rejects_unknown_severity():
    with pytest.raises(ValueError, match="validation_severity_invalid"):
        ValidationVerdict.issue(
            submission_id="submission-10",
            valid=True,
            severity="catastrophic",
            impact_commitment="0ximpact",
            evidence_commitment="0xevidence",
            validator_image_hash="sha256:fixture-image",
        )
