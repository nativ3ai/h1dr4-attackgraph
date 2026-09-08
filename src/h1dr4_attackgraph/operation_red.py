from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from h1dr4_attackgraph.products import OperationRedScope


class CampaignStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    FUNDED = "funded"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    VERIFYING = "verifying"
    REPORTED = "reported"


class OperationRedCampaignStore:
    """Receipt-gated Operation Red control plane with immutable campaign scope."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS operation_red_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    scope_hash TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    budget_usdc_micros INTEGER NOT NULL,
                    funded_usdc_micros INTEGER NOT NULL DEFAULT 0,
                    approved_by TEXT NOT NULL DEFAULT '',
                    report_ref TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operation_red_receipts (
                    receipt_ref TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    amount_usdc_micros INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL,
                    FOREIGN KEY(campaign_id) REFERENCES operation_red_campaigns(campaign_id)
                );
                """
            )

    def create(self, scope: OperationRedScope) -> dict[str, Any]:
        canonical = scope.canonical()
        scope_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        scope_hash = "0x" + hashlib.sha256(scope_json.encode()).hexdigest()
        campaign_id = f"redop_{uuid.uuid4().hex}"
        now = datetime.now(UTC).isoformat()
        plan_json = json.dumps(scope.dispatch_plan(), sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO operation_red_campaigns (
                    campaign_id, scope_hash, scope_json, plan_json, status,
                    budget_usdc_micros, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    scope_hash,
                    scope_json,
                    plan_json,
                    CampaignStatus.DRAFT.value,
                    scope.budget_usdc_micros,
                    now,
                    now,
                ),
            )
        return self.get(campaign_id)

    def get(self, campaign_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM operation_red_campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise KeyError("operation_campaign_not_found")
            receipt_rows = connection.execute(
                """
                SELECT receipt_ref, amount_usdc_micros, recorded_at
                FROM operation_red_receipts WHERE campaign_id=? ORDER BY recorded_at
                """,
                (campaign_id,),
            ).fetchall()
        scope_json = row["scope_json"]
        expected_hash = "0x" + hashlib.sha256(scope_json.encode()).hexdigest()
        if expected_hash != row["scope_hash"]:
            raise ValueError("operation_scope_integrity_failure")
        return {
            "campaign_id": row["campaign_id"],
            "scope_hash": row["scope_hash"],
            "scope": json.loads(scope_json),
            "dispatch_plan": json.loads(row["plan_json"]),
            "status": row["status"],
            "budget_usdc_micros": row["budget_usdc_micros"],
            "funded_usdc_micros": row["funded_usdc_micros"],
            "approved_by": row["approved_by"],
            "report_ref": row["report_ref"],
            "receipts": [dict(item) for item in receipt_rows],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def approve(self, campaign_id: str, *, approved_by: str) -> dict[str, Any]:
        if not approved_by.strip():
            raise ValueError("operation_approver_required")
        self._transition(
            campaign_id,
            expected={CampaignStatus.DRAFT},
            status=CampaignStatus.APPROVED,
            updates={"approved_by": approved_by.strip()},
        )
        return self.get(campaign_id)

    def record_funding(
        self,
        campaign_id: str,
        *,
        receipt_ref: str,
        amount_usdc_micros: int,
    ) -> dict[str, Any]:
        if not receipt_ref.strip() or amount_usdc_micros <= 0:
            raise ValueError("operation_funding_receipt_invalid")
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM operation_red_campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise KeyError("operation_campaign_not_found")
            if row["status"] not in {
                CampaignStatus.APPROVED.value,
                CampaignStatus.FUNDED.value,
            }:
                raise ValueError("operation_campaign_transition_invalid")
            funded = row["funded_usdc_micros"] + amount_usdc_micros
            if funded > row["budget_usdc_micros"]:
                raise ValueError("operation_funding_exceeds_budget")
            try:
                connection.execute(
                    """
                    INSERT INTO operation_red_receipts (
                        receipt_ref, campaign_id, amount_usdc_micros, recorded_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (receipt_ref.strip(), campaign_id, amount_usdc_micros, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("operation_funding_receipt_duplicate") from exc
            status = (
                CampaignStatus.FUNDED.value
                if funded == row["budget_usdc_micros"]
                else CampaignStatus.APPROVED.value
            )
            connection.execute(
                """
                UPDATE operation_red_campaigns
                SET funded_usdc_micros=?, status=?, updated_at=?
                WHERE campaign_id=?
                """,
                (funded, status, now, campaign_id),
            )
        return self.get(campaign_id)

    def schedule(self, campaign_id: str) -> dict[str, Any]:
        self._transition(
            campaign_id,
            expected={CampaignStatus.FUNDED},
            status=CampaignStatus.SCHEDULED,
        )
        return self.get(campaign_id)

    def dispatch(self, campaign_id: str) -> list[dict[str, Any]]:
        self._transition(
            campaign_id,
            expected={CampaignStatus.SCHEDULED},
            status=CampaignStatus.RUNNING,
        )
        return self.get(campaign_id)["dispatch_plan"]

    def begin_verification(self, campaign_id: str) -> dict[str, Any]:
        self._transition(
            campaign_id,
            expected={CampaignStatus.RUNNING},
            status=CampaignStatus.VERIFYING,
        )
        return self.get(campaign_id)

    def mark_reported(self, campaign_id: str, *, report_ref: str) -> dict[str, Any]:
        if not report_ref.strip():
            raise ValueError("operation_report_reference_required")
        self._transition(
            campaign_id,
            expected={CampaignStatus.VERIFYING},
            status=CampaignStatus.REPORTED,
            updates={"report_ref": report_ref.strip()},
        )
        return self.get(campaign_id)

    def _transition(
        self,
        campaign_id: str,
        *,
        expected: set[CampaignStatus],
        status: CampaignStatus,
        updates: dict[str, Any] | None = None,
    ) -> None:
        values = dict(updates or {})
        values["status"] = status.value
        values["updated_at"] = datetime.now(UTC).isoformat()
        assignments = ", ".join(f"{key}=?" for key in values)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM operation_red_campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise KeyError("operation_campaign_not_found")
            if row["status"] not in {item.value for item in expected}:
                raise ValueError("operation_campaign_transition_invalid")
            connection.execute(
                f"UPDATE operation_red_campaigns SET {assignments} WHERE campaign_id=?",
                (*values.values(), campaign_id),
            )
