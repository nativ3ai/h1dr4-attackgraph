# Validation record

Latest local validation: 2026-09-08 from a non-FileProvider macOS workspace.

## Automated

```text
ruff: all checks passed
pytest: 58 passed
package: sdist and wheel build successfully
dashboard: lint and production build succeeded in the latest main CI
```

The suite covers:

- Sibyl recall through a fresh client instance.
- Deterministic tenant isolation between operators.
- Deletion proof against a new/empty Sibyl database.
- Secret redaction before persistence.
- Manual-only non-execution and autonomous human approval.
- Exact target/lane and destructive-pattern policy checks.
- Model-free initialization and compact agent briefs.
- H3RETIK job creation/result ingestion through a mocked adapter.
- The exported MCP tool surface.
- Dashboard snapshot mapping and local API behavior.
- Hashed, revocable agent tokens and engagement membership enforcement.
- Per-agent Sibyl attribution and denial of cross-engagement access.
- Dashboard creation of agents, single-use invites, and H3RETIK session bindings.
- Model-agnostic `h1dr4.telemetry.v1` contract and MCP tool export.
- Assertion deduplication and in-place H3RETIK attestation promotion.
- Adapter-only authentication before accepting H3RETIK executor claims.
- Exact target, action, and bound-session correlation for verified evidence.
- Nested secret redaction across agent attributes and executor proof.
- Typed event, worker, session, job, room, and relationship projection into the dashboard.
- Operation Red scope and derived-plan integrity checks.
- Rejection of caller-asserted funding and exact H3RETIK paid-receipt validation.
- Per-module worker/session/job reconciliation without bearer-token persistence.
- Schedule-window enforcement before worker dispatch.
- Automatic verified executor telemetry plus asserted semantic findings and loot.
- Report delivery gating and the AgentMail send adapter.

## Operation Red deterministic end-to-end

The local suite executes a complete three-worker campaign with a deterministic
H3RETIK transport: `web`, `verification`, and `reporting`. It quotes and creates
the same worker receipt shape as the hosted MCP, syncs independently paid
Base/USDC receipts, binds separate H3RETIK session and worker IDs, runs each
worker, parses its completion envelope, and writes correlated execution,
finding, and artifact events into the real local Sibyl database.

The test proves the orchestration and trust boundaries without spending funds
or touching a target. It deliberately keeps model-authored findings asserted
while executor completion records become verified. The final state changes to
`reported` only after the report adapter returns a message reference. The test
also scans the campaign database bytes and confirms that the fake H3RETIK bearer
tokens were never persisted.

This does not claim a newly paid live three-worker campaign. The live hosted
runtime proof below and this orchestration proof are separate until a company
funds the full specialist campaign.

## MCP transport

A real stdio client opened an engagement, stopped the server, started separate
server processes for subsequent calls, and recovered `MCP-FRESH-001` from the
same Sibyl database. This validates protocol negotiation and fresh-process
recall rather than only direct Python calls.

A second real stdio smoke exercised `h1dr4.telemetry.v1`: an agent assertion was
stored, a bad executor credential was rejected, and an authenticated H3RETIK
payload with the same idempotency key promoted the same event to `verified`.
The final Sibyl graph contained one telemetry record and six typed provenance
relationships, not duplicate assertion and proof records.

## Live read-only adapters

The live H1DR4 endpoint returned these matches for `osint`:

```text
h1dr4_osint_capabilities
h1dr4_osint_prepare
h1dr4_osint_agent
```

The live H3RETIK endpoint advertised 38 tools. On 2026-09-08 a fresh read-only
worker quote confirmed all four worker tools, a `7.0 USDC` micro-worker quote,
manual `openai/gpt-5.6-sol`, `terminal,file`, and `blockrun-x402`. The initial
read-only
preflight quoted a 5-minute, 3-action Europe window at `0.19 USDC` without
accepting terms or spending funds. The separately authorized paid lifecycle is
recorded below.

## Paid H3RETIK Cloud execution

The wallet operator personally accepted H3RETIK ToS v1 and funded receipt
`rcpt-788c547069da4c0db1` with `1.05 USDC` on Base. It activated Europe session
`ses-c5e1210dcd37` for 30 minutes and 15 actions.

The default disposable image was confirmed intentionally lean: it contained no
Docker, Podman, Node, npm, Python, curl, or git. A session tool lease installed
Node, npm, curl, and CA roots inside each fresh job. The job downloaded the
official OWASP Juice Shop v20.2.0 Node 22 Linux package, verified SHA-256
`b52e327b15f5be7448dd36ac2da5259893e4dbb3c0c009dda45bd23bde114c7a`,
and bound the application to loopback inside the disposable environment.

H3RETIK job `job-671651c129a6` independently confirmed four challenge states:

- `directoryListingChallenge` — Confidential Document.
- `loginAdminChallenge` — Login Admin.
- `securityPolicyChallenge` — Security Policy.
- `exposedMetricsChallenge` — Exposed Metrics.

ATTACKGRAPH materialized the three security findings separately from the
informational policy checkpoint. It stored two sealed artifact records as
metadata and hashes, not raw document or authentication payloads. The Sibyl
graph contained nine verified telemetry events, three findings, two artifacts,
and the proof-derived posture `target_compromised`. A separate Python process
reopened the same database and reconstructed the engagement and proof sources;
the raw H3RETIK bearer token was absent from the database bytes.

### Issues found and corrected

The first ATTACKGRAPH-dispatched job, `job-ab9381db06da`, outlived the client's
fixed 120-second polling deadline. Google Batch reached `SUCCEEDED` after about
170 seconds, while the H3RETIK API recorded the terminal result after about 203
seconds. Polling now derives its deadline from the approved action runtime plus
cold-provisioning and leased-tool headroom.

The live regression job `job-acb2e4e93e1a` exposed a second boundary. Google
Batch reached `SUCCEEDED` after about 175 seconds, but repeated polling through
the hosted H3RETIK MCP did not surface the terminal state within 300 seconds;
the REST status lookup reconciled it after approximately 314 seconds. The
ATTACKGRAPH headroom was raised to five minutes and is regression-tested. A
follow-up H3RETIK patch now routes both MCP and REST reads through one provider
reconciler and exposes `provider_state` plus `last_synced_at`. That backend patch
is locally tested but remains unverified on the hosted endpoint until deployed.
Leased tools should still be cached/prebuilt where practical instead of
installed afresh for every job.

The same local contract tests attach two disposable sessions to one workspace,
create a job from each, and verify both jobs inherit the durable engagement ID.
Additional tests prove a funded extension receipt keeps the original session,
adds actions/runtime, and advances its receipt-issued bearer expiry.

Both jobs were reconciled into their original scoped actions only after the
backend reported `succeeded`. Remote failure status and exit codes are no longer
hard-coded as successful during ingestion.

After the paid session and 30-second grace period elapsed, the same bearer was
rejected with `expired_bearer_token`. A direct infrastructure check found no
Compute Engine instances in the project; all five Google Batch resources used
by the test were terminal `SUCCEEDED`. This proves command access was revoked
and no worker VM remained. The retained Batch job metadata is audit state, not
a running machine. The public API still lacks an explicit early-dispose command
and signed destruction receipt.
