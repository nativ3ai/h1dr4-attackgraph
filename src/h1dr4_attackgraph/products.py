from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ProductSurface(StrEnum):
    ATTACKGRAPH = "attackgraph"
    OPERATION_RED = "operation_red"
    PROOFVAULT = "proofvault"


class ModuleRisk(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    HIGH_IMPACT = "high_impact"


@dataclass(frozen=True, slots=True)
class RedModule:
    module_id: str
    label: str
    lane: str
    risk: ModuleRisk
    tool_pack: str
    model_role: str
    capabilities: tuple[str, ...]


MODULE_REGISTRY: dict[str, RedModule] = {
    item.module_id: item
    for item in (
        RedModule(
            "osint",
            "OSINT + asset discovery",
            "osint",
            ModuleRisk.PASSIVE,
            "osint-lean",
            "reconnaissance",
            ("dns.read", "http.metadata", "public.search", "registry.read"),
        ),
        RedModule(
            "web",
            "Web surface",
            "web",
            ModuleRisk.ACTIVE,
            "web-lean",
            "web_operator",
            ("http.request", "browser.navigate", "web.crawl", "web.safe_probe"),
        ),
        RedModule(
            "api_mcp",
            "API + MCP boundaries",
            "api",
            ModuleRisk.ACTIVE,
            "api-lean",
            "api_operator",
            ("schema.read", "api.request", "mcp.discover", "mcp.call_scoped"),
        ),
        RedModule(
            "contract",
            "Smart-contract analysis",
            "contract",
            ModuleRisk.ACTIVE,
            "evm-lean",
            "contract_operator",
            ("source.read", "bytecode.read", "fork.execute", "invariant.test"),
        ),
        RedModule(
            "verification",
            "Independent verification",
            "verify",
            ModuleRisk.ACTIVE,
            "verify-lean",
            "verifier",
            ("evidence.read", "fork.execute", "reproduction.run", "verdict.attest"),
        ),
        RedModule(
            "reporting",
            "Evidence reporting",
            "report",
            ModuleRisk.PASSIVE,
            "report-lean",
            "reporter",
            ("evidence.read_redacted", "report.compose", "mail.send_scoped"),
        ),
    )
}


@dataclass(slots=True)
class OperationSchedule:
    starts_at: str
    ends_at: str
    timezone: str = "UTC"
    cadence_minutes: int = 0
    window_minutes: int = 30

    def validate(self) -> None:
        if not self.starts_at or not self.ends_at:
            raise ValueError("operation_schedule_window_required")
        if self.cadence_minutes < 0:
            raise ValueError("operation_schedule_cadence_invalid")
        if not 1 <= self.window_minutes <= 24 * 60:
            raise ValueError("operation_schedule_window_invalid")


@dataclass(slots=True)
class OperationRedScope:
    company_id: str
    workspace_id: str
    targets: list[str]
    modules: list[str]
    schedule: OperationSchedule
    budget_usdc_micros: int
    max_requests_per_second: int = 2
    credentials_ref: str = ""
    prohibited_actions: list[str] = field(
        default_factory=lambda: [
            "destructive_actions",
            "persistence",
            "unapproved_lateral_movement",
            "production_data_exfiltration",
            "denial_of_service",
        ]
    )
    retention_hours: int = 168

    def validate(self) -> None:
        self.schedule.validate()
        if not self.company_id.strip() or not self.workspace_id.strip():
            raise ValueError("operation_identity_required")
        self.targets = list(dict.fromkeys(item.strip() for item in self.targets if item.strip()))
        if not self.targets:
            raise ValueError("operation_target_required")
        self.modules = list(dict.fromkeys(self.modules))
        unknown = [item for item in self.modules if item not in MODULE_REGISTRY]
        if unknown:
            raise ValueError(f"operation_unknown_modules:{','.join(unknown)}")
        if "verification" not in self.modules or "reporting" not in self.modules:
            raise ValueError("operation_verification_and_reporting_required")
        if self.budget_usdc_micros <= 0:
            raise ValueError("operation_budget_required")
        if not 1 <= self.max_requests_per_second <= 50:
            raise ValueError("operation_rate_limit_invalid")
        if not 1 <= self.retention_hours <= 24 * 365:
            raise ValueError("operation_retention_invalid")

    def canonical(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["targets"] = sorted(self.targets)
        value["modules"] = sorted(self.modules)
        value["prohibited_actions"] = sorted(set(self.prohibited_actions))
        return value

    def scope_hash(self) -> str:
        payload = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return "0x" + hashlib.sha256(payload.encode()).hexdigest()

    def dispatch_plan(self) -> list[dict[str, Any]]:
        self.validate()
        allocation, remainder = divmod(self.budget_usdc_micros, len(self.modules))
        return [
            {
                "agent_id": f"{self.workspace_id}:{module_id}",
                "workspace_id": self.workspace_id,
                "module_id": module_id,
                "lane": MODULE_REGISTRY[module_id].lane,
                "risk": MODULE_REGISTRY[module_id].risk.value,
                "tool_pack": MODULE_REGISTRY[module_id].tool_pack,
                "model_role": MODULE_REGISTRY[module_id].model_role,
                "capabilities": list(MODULE_REGISTRY[module_id].capabilities),
                "targets": list(self.targets),
                "budget_usdc_micros": allocation + (1 if index < remainder else 0),
                "schedule": asdict(self.schedule),
            }
            for index, module_id in enumerate(self.modules)
        ]
