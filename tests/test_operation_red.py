from __future__ import annotations

import pytest

from h1dr4_attackgraph.operation_red import OperationRedCampaignStore
from h1dr4_attackgraph.products import OperationRedScope, OperationSchedule


def create_scope() -> OperationRedScope:
    return OperationRedScope(
        company_id="company-fixture",
        workspace_id="workspace-fixture",
        targets=["owned.example.test"],
        modules=["web", "verification", "reporting"],
        schedule=OperationSchedule(
            starts_at="2026-09-06T10:00:00Z",
            ends_at="2026-09-06T12:00:00Z",
        ),
        budget_usdc_micros=3_000_000,
    )


def test_campaign_requires_approval_and_exact_funding_before_dispatch(tmp_path):
    store = OperationRedCampaignStore(tmp_path / "operation-red.db")
    campaign = store.create(create_scope())
    campaign_id = campaign["campaign_id"]

    assert campaign["status"] == "draft"
    original_scope_hash = campaign["scope_hash"]
    with pytest.raises(ValueError, match="operation_campaign_transition_invalid"):
        store.record_funding(
            campaign_id,
            receipt_ref="base:before-approval",
            amount_usdc_micros=1_000_000,
        )

    assert store.approve(campaign_id, approved_by="owner-passkey")["status"] == "approved"
    partial = store.record_funding(
        campaign_id,
        receipt_ref="base:receipt-one",
        amount_usdc_micros=1_000_000,
    )
    assert partial["status"] == "approved"
    assert partial["funded_usdc_micros"] == 1_000_000
    with pytest.raises(ValueError, match="operation_campaign_transition_invalid"):
        store.schedule(campaign_id)

    funded = store.record_funding(
        campaign_id,
        receipt_ref="base:receipt-two",
        amount_usdc_micros=2_000_000,
    )
    assert funded["status"] == "funded"
    assert funded["scope_hash"] == original_scope_hash
    assert store.schedule(campaign_id)["status"] == "scheduled"

    plan = store.dispatch(campaign_id)

    assert {item["module_id"] for item in plan} == {"web", "verification", "reporting"}
    assert sum(item["budget_usdc_micros"] for item in plan) == 3_000_000
    assert store.get(campaign_id)["status"] == "running"


def test_campaign_rejects_duplicate_receipts_and_overfunding(tmp_path):
    store = OperationRedCampaignStore(tmp_path / "operation-red.db")
    campaign_id = store.create(create_scope())["campaign_id"]
    store.approve(campaign_id, approved_by="owner-passkey")
    store.record_funding(
        campaign_id,
        receipt_ref="base:unique",
        amount_usdc_micros=1_000_000,
    )

    with pytest.raises(ValueError, match="operation_funding_receipt_duplicate"):
        store.record_funding(
            campaign_id,
            receipt_ref="base:unique",
            amount_usdc_micros=1_000_000,
        )
    with pytest.raises(ValueError, match="operation_funding_exceeds_budget"):
        store.record_funding(
            campaign_id,
            receipt_ref="base:too-much",
            amount_usdc_micros=3_000_000,
        )


def test_campaign_verification_and_report_are_ordered(tmp_path):
    store = OperationRedCampaignStore(tmp_path / "operation-red.db")
    campaign_id = store.create(create_scope())["campaign_id"]
    store.approve(campaign_id, approved_by="owner-passkey")
    store.record_funding(
        campaign_id,
        receipt_ref="base:full",
        amount_usdc_micros=3_000_000,
    )
    store.schedule(campaign_id)
    store.dispatch(campaign_id)

    assert store.begin_verification(campaign_id)["status"] == "verifying"
    reported = store.mark_reported(campaign_id, report_ref="agentmail:message-fixture")

    assert reported["status"] == "reported"
    assert reported["report_ref"] == "agentmail:message-fixture"
