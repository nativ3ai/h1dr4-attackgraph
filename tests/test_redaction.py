from __future__ import annotations

from h1dr4_attackgraph.redaction import redact


def test_typed_integrity_values_survive_secret_redaction():
    digest = "sha256:" + "a" * 64
    commitment = "0x" + "b" * 64

    result = redact({"digest": digest, "report_commitment": commitment})

    assert result == {"digest": digest, "report_commitment": commitment}


def test_private_keys_and_untyped_hex_material_remain_redacted():
    private_key = "c" * 64
    result = redact(
        {
            "private_key": private_key,
            "notes": f"untyped material {private_key}",
            "hash": "secret=fixture-secret",
        }
    )

    assert result["private_key"] == "[REDACTED]"
    assert result["notes"] == "untyped material [REDACTED]"
    assert result["hash"] == "secret=[REDACTED]"
