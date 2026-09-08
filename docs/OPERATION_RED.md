# Operation Red control plane

Operation Red is the managed red-team campaign path. It coordinates paid,
disposable H3RETIK workers; it does not replace AttackGraph or Sibyl.

## Trust boundaries

1. The company supplies a target allowlist, modules, schedule, rate ceiling,
   prohibited actions, and maximum budget.
2. `OperationRedCampaignStore.create` canonicalizes and hashes that scope.
3. A human approval identity approves that immutable hash.
4. `OperationRedOrchestrator.prepare_receipts` creates one H3RETIK worker
   receipt per module. Each worker uses the `h1dr4-worker-pack` `redteam`
   profile, BlockRun inference, and bounded Hermes toolsets.
5. `sync_funding` asks H3RETIK to verify each Base receipt. A caller-entered
   amount, screenshot, or transaction claim is not accepted as funding.
6. At dispatch, the orchestrator re-syncs every receipt before changing the
   campaign to `running`. It verifies the receipt ID, amount, wallet, Base/USDC
   asset, worker ID, and session ID.
7. The paid token is passed directly to H3RETIK and discarded after the call.
   Tokens are not stored in the Operation Red database or Sibyl.
8. Every module has a scoped AttackGraph action. Executor completion becomes a
   verified Sibyl event only when its H3RETIK attestation correlates with that
   action. Findings and loot parsed from the model response remain assertions.
9. The campaign enters `reported` only after the report sender returns a stable
   provider message reference.

## State machine

```text
draft -> approved -> funded -> scheduled -> running -> verifying -> reported
           |           |           |           |
           |           |           |           +-- per-worker success/failure
           |           |           +-- enforced UTC execution window
           |           +-- all assigned H3RETIK receipts verified paid
           +-- receipts may be prepared, but no worker can run
```

Worker assignments retain operational metadata only: module, lane, receipt,
wallet, worker/session/job IDs, status, error, evidence digest, and telemetry
event ID. Report delivery retains its channel, recipient, status, evidence
digest, and provider reference.

## Python integration

```python
from h1dr4_attackgraph import OperationRedCampaignStore, OperationRedOrchestrator
from h1dr4_attackgraph.h3retik import H3retikClient

store = OperationRedCampaignStore(".attackgraph/operation-red.db")
orchestrator = OperationRedOrchestrator(
    store=store,
    h3retik=H3retikClient(),
    attackgraph=attackgraph_service,
)

campaign = store.create(scope)
store.approve(campaign["campaign_id"], approved_by=passkey_credential_id)
quote = orchestrator.quote_campaign(campaign["campaign_id"])
prepared = orchestrator.prepare_receipts(campaign["campaign_id"], wallet=wallet)
# Fund each prepared assignment's receipt address on Base.
funded = orchestrator.sync_funding(campaign["campaign_id"])
store.schedule(campaign["campaign_id"])
result = orchestrator.dispatch(campaign["campaign_id"])
reported = orchestrator.deliver_report(
    campaign["campaign_id"],
    recipient="security@example.com",
    sender=report_sender,
)
```

The forthcoming H1DR4 assignment page should call these operations from its
authenticated server. It must not expose `approve`, paid receipt auth, or
dispatch as unauthenticated browser or agent MCP tools.

## Verification

Run the deterministic integration test without paying or contacting a target:

```bash
uv run pytest tests/test_operation_red.py -q
```

The test proves receipt mismatch rejection, schedule enforcement, three worker
jobs, scoped actions, verified executor telemetry, asserted semantic findings,
loot ingestion, report delivery acknowledgement, and absence of bearer tokens
from the campaign database.
