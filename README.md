# H1DR4 ATTACKGRAPH

**The durable attack brain for any MCP-compatible agent.**

H1DR4 ATTACKGRAPH turns disconnected red-team searches, observations, failed
attempts, and sandbox output into a persistent engagement graph. The connected
agent reasons; ATTACKGRAPH remembers what matters, enforces scope, and can send
explicitly approved commands to a disposable H3RETIK Kali worker.

It is deliberately **model-agnostic**. Claude, Codex, Hermes/Qwen, or another
MCP host can use the same server. No local model is required.

## Why this exists

Red-team agents are often clever within one context window and forgetful across
the engagement. They repeat exhausted approaches, lose evidence provenance, and
mix speculative hypotheses with confirmed findings. ATTACKGRAPH makes memory a
load-bearing part of the loop:

```text
MCP agent ── typed semantic events ──▶ ATTACKGRAPH validator
                                            │
H3RETIK ── optional executor proof ─────────┤
                                            ▼
                                      Sibyl Memory
                                  hot graph + cold event log
                                            │
                                            ▼
                                  operator dashboard + MCP brief
```

The output is not a wall of notes. `attackgraph_get_brief` returns a compact,
structured handoff: confirmed facts, open hypotheses, exhausted paths, pending
actions, regression checks, and evidence provenance. A fresh agent session can
continue where the previous one stopped.

The local ATTACKGRAPH dashboard gives the human operator the same shared brain:
an interactive attack topology, confidence-separated intelligence, exhausted
paths, evidence chronology, per-worker attribution, H3RETIK session tracking,
regressions, and JSON export. It also manages passkeys, team invites, and
revocable MCP agent identities. It binds locally by default.

## Safety modes

| Mode | Intended use | Command behavior |
|---|---|---|
| `manual_only` | Gray Swan and human-assisted arenas | Records plans; never dispatches |
| `local_lab` | Human-operated local targets | Records plans for a local runner |
| `autonomous_lab` | Owned/authorized sandbox targets | H3RETIK dispatch only after human approval |

Every action is checked against an exact target allowlist and allowed execution
lanes. Actions marked destructive and known destructive command patterns are
denied. ATTACKGRAPH never accepts H3RETIK terms, buys compute, or submits arena
answers on the user's behalf.

## Quick start

Requirements: Python 3.11+, `uv`, Node.js 22.13+, and npm. Node is only used
for the local operator dashboard; the MCP server itself is Python.

```bash
git clone https://github.com/nativ3ai/h1dr4-attackgraph
cd h1dr4-attackgraph
uv sync --extra dev
cp .env.example .env
uv run h1dr4-attackgraph
```

Local use requires no API key, wallet, hosted model, or external database.
Sibyl Memory runs in-process and stores the engagement in the local SQLite file
selected by `ATTACKGRAPH_DB_PATH`. The default `.env.example` is enough to start
an unclaimed local dashboard.

### Optional integrations and credentials

| Capability | What it needs |
|---|---|
| Local MCP server, Sibyl memory, dashboard, exports | Nothing beyond the installed dependencies |
| Passkey-locked dashboard | A compatible browser/device and the local RP/origin values; no API key |
| H1DR4 public discovery tools | Network access to `https://h1dr4.dev/mcp`; no private key |
| H3RETIK quotes and capability discovery | Network access to the public H3RETIK MCP |
| H3RETIK command execution | A paid session, its wallet/token/session ID, and separate human approval + executor-attestation secrets |
| AgentMail report delivery for managed Operation Red | An AgentMail API key and inbox ID supplied only to the report adapter |
| Base settlement or ProofVault deployment | A user-controlled wallet only when that optional on-chain action is performed |

The agent never needs direct access to the H3RETIK bearer token, the executor
attestation secret, an AgentMail key, or a wallet private key.

Example MCP configuration:

```json
{
  "mcpServers": {
    "h1dr4-attackgraph": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/h1dr4-attackgraph", "run", "h1dr4-attackgraph"],
      "env": {
        "ATTACKGRAPH_DB_PATH": "/absolute/path/attackgraph/sibyl.db",
        "ATTACKGRAPH_OPERATOR_ID": "your-operator-id"
      }
    }
  }
}
```

Start with these MCP calls:

1. `attackgraph_open_engagement`
2. `attackgraph_get_reporting_contract` once per fresh agent session
3. `attackgraph_get_brief` whenever the agent needs a compact state refresh
4. `attackgraph_request_action` before any active test
5. `attackgraph_report_event` after meaningful executions, attempts, findings,
   loot, and checkpoints
6. `attackgraph_create_regression` after a finding is verified

The agent supplies meaning; it does not self-certify proof. Agent reports are
`asserted`, H3RETIK results without action correlation are `attested`, and only
complete executor evidence tied to a scoped action is `verified`. See
[docs/TELEMETRY_V1.md](docs/TELEMETRY_V1.md) for the full contract and examples.

### Evidence-derived engagement posture

The dashboard headline is the current verified posture, never a suggested next
action or a team-authored status. Sibyl derives reconnaissance, mapped-surface,
confirmed-finding, and access-material states from high-confidence typed
telemetry. Hypotheses, job titles, and free-form text cannot change it.

Higher-impact states require a successful, proof-bearing `finding.confirmed`
event submitted through `attackgraph_ingest_h3retik_event`. For example, its
attributes can declare the state supported by that proof:

```json
{
  "event_type": "finding.confirmed",
  "status": "completed",
  "exit_code": 0,
  "action_id": "act-example",
  "attributes": {"posture_signal": "foothold_active"},
  "idempotency_key": "finding:fixture-shell"
}
```

The server attaches the H3RETIK proof reference and evidence digest; the agent
cannot set `verified` itself. The executor intake also requires a separate
adapter credential that is never included in agent MCP configurations. The
engine accepts `initial_access_established`, `foothold_active`,
`privileged_access`, `target_compromised`, `objective_complete`, and
`regression_detected`. Every displayed transition links back to its Sibyl
record, source, worker, and timestamp through **WHY THIS STATE**.

### Run the dashboard

```bash
./scripts/run-dashboard.sh
```

Open `http://localhost:3000`. The API and interface read the database selected
by `ATTACKGRAPH_DB_PATH` and the tenant selected by
`ATTACKGRAPH_OPERATOR_ID`. Both services bind to the local machine; engagement
data is not deployed to a hosted dashboard.

On first launch, claim the console with a passkey or continue in unclaimed
local mode. The browser delegates Touch ID, Face ID, Windows Hello, security
keys, and nearby-device QR to the operating system. ATTACKGRAPH stores the
public credential and a hashed browser-session token, never a password.

### Connect an agent

1. Open **IDENTITY** in the dashboard.
2. Create a named agent for the active engagement.
3. Copy the generated MCP configuration. Its token is shown once.
4. Add that configuration to any MCP-compatible host and restart the host.

Each agent has an independent, revocable token. Its MCP process can only read
and write engagements where that agent has membership, and every observation,
hypothesis, attempt, action, and Sibyl event carries its agent identity. Do not
share the underlying H3RETIK credential with agents; ATTACKGRAPH remains the
broker and human approval boundary.

The same panel creates single-use 24-hour human invite links and records which
H3RETIK session IDs belong to the engagement. The engagement ID is also the
durable H3RETIK workspace ID, so multiple disposable sessions contribute jobs
to one combined operation. Session bindings are operational metadata only;
H3RETIK wallet and access credentials stay in environment variables outside
the dashboard.

### Private multiplayer workspaces

AttackGraph can synchronize an engagement between operators without uploading
the Sibyl database or plaintext intelligence. Each device keeps its own local
Sibyl. The H1DR4 relay stores only AES-256-GCM encrypted, Ed25519-signed
workspace snapshots, opaque identifiers, cursors, and membership metadata.

Host an existing engagement and create a one-use operator invite:

```bash
uv run attackgraph host eng-example --name WEB-01
uv run attackgraph invite eng-example --role operator --hours 24
```

On another machine, using the same absolute database and relay-state paths as
its MCP configuration:

```bash
uv run attackgraph join 'h1dr4-ag1:REDACTED' --name AUTH-02
uv run attackgraph status
```

The same host, invite, join, sync, member-list, and revoke operations are
available as MCP tools, so a fresh Codex can join without leaving the agent
workflow.

The invite code contains key material and must be treated as a secret. Relay
access tokens and workspace keys are kept in the mode-0600 file selected by
`ATTACKGRAPH_RELAY_STATE_PATH`; they are never written to Sibyl or returned by
an MCP status tool. After joining, ordinary MCP reads pull remote events before
building a brief, while writes merge and publish a new encrypted snapshot.
Local reads and writes remain available if the relay is temporarily offline.

See [docs/PRIVATE_RELAY.md](docs/PRIVATE_RELAY.md) for the protocol, deployment
boundary, revocation limitation, and two-client smoke test.

For a locked deployment, set the relying-party values explicitly:

```bash
ATTACKGRAPH_AUTH_MODE=passkey
ATTACKGRAPH_RP_ID=localhost
ATTACKGRAPH_ORIGIN=http://localhost:3000
```

## Sibyl is the product, not a log sink

Sibyl provides both sides of the attack brain:

- **Hot memory:** the current target graph, scope, hypotheses, findings,
  exhausted paths, pending actions, and regressions.
- **Cold memory:** append-only observations, attempts, policy decisions, and
  H3RETIK evidence with timestamps and provenance.
- **Isolation:** each operator gets a deterministic Sibyl tenant; engagements do
  not leak across operators.
- **Recall:** a new ATTACKGRAPH process reconstructs the engagement from Sibyl.

The deletion test in the suite proves the dependency: point the service at a
new Sibyl database and it cannot reconstruct the old brief.

```bash
uv run pytest tests/test_memory.py -k deletion
```

## H3RETIK integration

H3RETIK is the disposable execution plane, not the brain. The operator first
accepts its terms and provisions a compute session outside ATTACKGRAPH. Then:

1. Attach each paid session with `attackgraph_bind_h3retik_session`.
2. The agent drafts a command with `attackgraph_request_action` and selects a session.
3. ATTACKGRAPH checks mode, exact target, lane, risk, and destructive patterns.
4. A human supplies the server-side approval code.
5. The adapter creates and starts a scoped job in the selected H3RETIK session.
6. Sanitized output returns through `attackgraph_ingest_h3retik_event`; the
   server computes a digest and promotes the matching Sibyl assertion in place.

Sessions can be topped up without replacement.
`attackgraph_create_h3retik_extension_receipt` returns a Base funding address;
after the operator pays, `attackgraph_sync_h3retik_receipt` extends the same
session and its auth deadline.

Credentials and approval codes are environment-only. They are never returned by
an MCP tool or written to Sibyl. See [docs/H3RETIK_RUNBOOK.md](docs/H3RETIK_RUNBOOK.md).

## Operation Red

Operation Red is the managed campaign path. A company defines an exact target
allowlist, module set, time window, request-rate ceiling, prohibited actions,
and maximum USDC budget. That canonical scope is hashed before approval.

Each module receives a separate H3RETIK worker receipt and worker identity. The
control plane accepts funding only after H3RETIK verifies the Base receipt and
returns the paid session and worker IDs. Bearer tokens are used only in memory
while dispatching and are never written to the campaign database or Sibyl.

The run order is operational modules, independent verification, then reporting.
H3RETIK execution attestations tied to the approved action become verified
telemetry; model-authored findings remain assertions until reproducible proof
promotes them. A campaign is marked reported only after its delivery provider
returns a message reference. AgentMail delivery uses the official inbox send
endpoint through `AgentMailReportSender`.

See [docs/OPERATION_RED.md](docs/OPERATION_RED.md) for the state machine,
integration API, credential boundary, and deterministic end-to-end test.

## H1DR4 integration

`attackgraph_discover_h1dr4_tools` reads the live H1DR4 MCP capability list and
filters it by keyword. This lets the connected agent discover useful H1DR4 tools
without hard-coding a rapidly changing catalog.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest
npm --prefix dashboard install
npm --prefix dashboard run lint
npm --prefix dashboard run build
```

See [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md) for the hackathon demo and
[PRIOR_WORK.md](PRIOR_WORK.md) for the build-window disclosure. Current test and
live-adapter evidence is recorded in [docs/VALIDATION.md](docs/VALIDATION.md).

## Status

Hackathon prototype. Use only on systems you own or are explicitly authorized
to test. The server does not make authorization decisions for you.

MIT License.
