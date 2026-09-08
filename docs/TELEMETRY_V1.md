# H1DR4 telemetry v1

`h1dr4.telemetry.v1` is the model-agnostic reporting contract between an MCP
agent, H3RETIK, Sibyl Memory, and the operator dashboard. It turns an agent's
work into typed engagement state without trusting free-form prose as proof.

## Responsibilities

| Component | Responsibility |
|---|---|
| MCP agent | Report the semantic meaning of work: execution, attempt, finding, loot, or checkpoint. |
| ATTACKGRAPH | Enforce engagement scope, validate the schema, redact secrets, deduplicate events, and correlate proof. |
| H3RETIK | Optionally supply executor facts: session, job, command, status, exit code, and sanitized evidence. |
| Sibyl Memory | Persist the typed event, materialized finding/attempt/loot record, relationships, actor, and proof provenance. |
| Dashboard | Render the same memory as rooms, feed events, workers, sessions, loot, and evidence-derived posture. |

The contract keeps four concerns separate:

| Field | Question answered | Operator result |
|---|---|---|
| `summary` | What changed? | Human-readable feed title and evidence label |
| `entities` + `relationships` | Where did it happen? | Stable rooms and typed paths on the target map |
| `artifact` | What was collected? | One typed item in the loot locker |
| H3RETIK attestation | Why should it be trusted? | Assurance, proof reference, digest, job and session provenance |

Transport text such as “imported H3RETIK result” is not semantic evidence. The
normalizer replaces that text with the reported technique, while H3RETIK
provenance remains in proof metadata.

H3RETIK is not required. Without it, the stack still provides useful shared
memory and attribution. Its events remain `asserted`. With H3RETIK evidence but
no scoped action, an event becomes `attested`. Only evidence correlated to a
previously scoped ATTACKGRAPH action can become `verified`.

The executor intake is a separate trust boundary. Calls to
`attackgraph_ingest_h3retik_event` require the adapter-only
`ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN`; ordinary agent workers must not receive
that credential. A server-generated digest then provides integrity for the
sanitized payload after authenticated intake.

## Agent loop

1. Read `attackgraph_get_reporting_contract` once per fresh agent session.
2. Read `attackgraph_get_brief` before planning so exhausted paths and existing
   evidence are load-bearing.
3. Call `attackgraph_request_action` before an active test.
4. Call `attackgraph_report_event` after each meaningful state change.
5. Reuse the same `idempotency_key` when H3RETIK later calls
   `attackgraph_ingest_h3retik_event` with proof for that event.
6. Write `checkpoint.written` before a phase, agent, or session ends.

The reporting grid is:

| When | Event type |
|---|---|
| Command starts | `execution.started` |
| Command finishes | `execution.completed` |
| A path was tested | `attempt.completed` |
| A possible issue appears | `finding.observed` |
| Evidence establishes an issue | `finding.confirmed` |
| An artifact is collected | `loot.discovered` |
| A phase or session ends | `checkpoint.written` |

## Agent assertion example

```json
{
  "engagement_id": "eng-example",
  "event_type": "finding.confirmed",
  "summary": "Owned fixture accepted an unauthorized administrator session",
  "target": "demo.internal",
  "outcome": "success",
  "technique": "authentication_bypass",
  "confidence": 0.98,
  "action_id": "act-example",
  "entities": [
    {"id": "backend", "type": "asset", "label": "Backend service", "layer": "application"},
    {"id": "login", "type": "endpoint", "label": "/login", "layer": "identity", "parent_id": "backend"}
  ],
  "relationships": [
    {"from": "backend", "to": "login", "type": "exposes"},
    {"from": "event", "to": "login", "type": "observed_on"}
  ],
  "attributes": {
    "posture_signal": "target_compromised",
    "http_status": 200
  },
  "idempotency_key": "finding:admin-auth-bypass"
}
```

Despite the event name, this first report is an assertion. It can materialize a
`finding_assertion` for review but cannot set the dashboard to `PWNED`.

## H3RETIK promotion example

```json
{
  "engagement_id": "eng-example",
  "event_type": "finding.confirmed",
  "summary": "Owned fixture accepted an unauthorized administrator session",
  "h3retik_session_id": "session-example",
  "job_id": "job-example",
  "command_id": "command-example",
  "status": "completed",
  "attestation_token": "adapter-only-secret",
  "exit_code": 0,
  "target": "demo.internal",
  "outcome": "success",
  "technique": "authentication_bypass",
  "action_id": "act-example",
  "attributes": {"posture_signal": "target_compromised"},
  "evidence": {"http_status": 200, "response_fingerprint": "sha256:..."},
  "idempotency_key": "finding:admin-auth-bypass"
}
```

ATTACKGRAPH computes the evidence digest server-side. If the session is bound,
the action exists, and the target/session correlation is valid, Sibyl promotes
the original event and materialized record in place. The dashboard then shows
the semantic event once, with verified proof provenance.

## Loot example

`loot.discovered` separates artifact metadata from the sealed payload. An agent
may reference an entity or earlier finding that already exists in the graph.

```json
{
  "engagement_id": "eng-example",
  "event_type": "loot.discovered",
  "summary": "Administrator API response captured",
  "outcome": "success",
  "technique": "response-capture",
  "relationships": [
    {"from": "event", "to": "login", "type": "observed_on"}
  ],
  "artifact": {
    "id": "artifact-admin-response",
    "type": "response",
    "label": "Administrator API response",
    "sensitivity": "sensitive",
    "entity_ids": ["login"],
    "finding_ids": ["obs-confirmed-finding"],
    "media_type": "application/json"
  },
  "idempotency_key": "loot:admin-response"
}
```

The artifact appears once in the loot locker. Its room and finding references
remain visible while payload evidence stays sealed until requested through the
artifact endpoint.

## Schema rules

- `target` must exactly match the engagement allowlist.
- `event_type`, `outcome`, entity types, and relationship types use the enums
  returned by `attackgraph_get_reporting_contract`.
- Reuse one opaque entity ID for the same target object across the engagement.
  Changing the type behind an existing ID is rejected.
- Relationships may reference `event`, `target`, an entity declared in the same
  event, or an entity/record already known to the engagement graph. Unknown
  references are rejected.
- `layer` is an optional semantic placement hint. The dashboard maps it onto
  target-appropriate floors; it is not screen geometry.
- `artifact` is accepted only on `loot.discovered`. It contains metadata and
  graph references, not raw secret material.
- Explicit idempotency keys must be stable, opaque identifiers. If omitted,
  ATTACKGRAPH derives a deterministic semantic fingerprint.
- Agent input cannot set `verified` or provide a trusted attestation.
- The H3RETIK adapter credential is authenticated before any executor event is
  accepted and is never written to Sibyl.
- High-impact posture requires a successful `finding.confirmed` event with exit
  code `0`, complete executor proof, and correlation to a scoped action.

## Secret policy

Report metadata, references, counts, status, and fingerprints. Do not report raw
credentials, cookies, bearer values, private keys, or authorization headers.
ATTACKGRAPH redacts common secret fields and patterns before Sibyl persistence,
including nested executor evidence. Dashboard snapshots keep proof metadata but
seal the raw proof payload.

## Compatibility

The older observation and attempt tools remain available, but they are legacy
assertion paths. A posture claim submitted through a legacy observation is
forced to unverified. New integrations should use the telemetry tools.
