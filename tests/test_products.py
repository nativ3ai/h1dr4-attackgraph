from __future__ import annotations

import pytest

from h1dr4_attackgraph.products import OperationRedScope, OperationSchedule


def operation_scope(**overrides) -> OperationRedScope:
    values = {
        "company_id": "company-demo",
        "workspace_id": "redop-demo",
        "targets": ["api.example.test", "api.example.test"],
        "modules": ["osint", "web", "verification", "reporting"],
        "schedule": OperationSchedule(
            starts_at="2026-09-05T09:00:00Z",
            ends_at="2026-09-05T13:00:00Z",
            cadence_minutes=60,
            window_minutes=20,
        ),
        "budget_usdc_micros": 20_000_000,
    }
    values.update(overrides)
    return OperationRedScope(**values)


def test_operation_scope_is_canonical_and_dispatches_specialists():
    scope = operation_scope()

    first_hash = scope.scope_hash()
    plan = scope.dispatch_plan()

    assert first_hash.startswith("0x") and len(first_hash) == 66
    assert scope.scope_hash() == first_hash
    assert scope.targets == ["api.example.test"]
    assert {item["module_id"] for item in plan} == {
        "osint",
        "web",
        "verification",
        "reporting",
    }
    assert [item["module_id"] for item in plan] == [
        "osint",
        "web",
        "verification",
        "reporting",
    ]
    assert sum(item["budget_usdc_micros"] for item in plan) == 20_000_000
    assert all(item["workspace_id"] == "redop-demo" for item in plan)
    assert next(item for item in plan if item["module_id"] == "web")["tool_pack"] == (
        "web-lean"
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"targets": []}, "operation_target_required"),
        ({"modules": ["web", "reporting"]}, "verification_and_reporting_required"),
        (
            {"modules": ["web", "verification", "reporting", "unknown"]},
            "operation_unknown_modules:unknown",
        ),
        ({"budget_usdc_micros": 0}, "operation_budget_required"),
    ],
)
def test_operation_scope_rejects_unsafe_or_incomplete_configuration(overrides, message):
    with pytest.raises(ValueError, match=message):
        operation_scope(**overrides).validate()
