# H3RETIK operator runbook

H3RETIK runs commands only in an existing, paid, disposable session. Provisioning
is intentionally outside the MCP server because accepting legal terms and
authorizing payment are human decisions.

## One-time operator setup

1. Read the current terms: `h3retik-cloud tos get`.
2. Accept them yourself if appropriate: `h3retik-cloud tos accept`.
3. Quote the smallest useful compute window.
4. Authorize payment and rent the session with the H3RETIK CLI.
5. Export the returned session ID, wallet address, and bearer token only in the
   environment that launches ATTACKGRAPH.

```bash
export H3RETIK_WALLET='0x...'
export H3RETIK_TOKEN='...'
export H3RETIK_SESSION_ID='...'
export ATTACKGRAPH_EXECUTION_APPROVAL_CODE='one-time-human-secret'
export ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN='separate-adapter-only-secret'
uv run h1dr4-attackgraph
```

Do not put these values in `.env` if that file could be copied or shared.

## Attach compute to the workspace

The AttackGraph engagement is the durable workspace. Attach every paid session
to the same engagement; sessions may use different lanes or regions but must
belong to the configured H3RETIK wallet.

```text
attackgraph_bind_h3retik_session(
  engagement_id="eng-...",
  session_id="ses-...",
  label="Europe web worker",
  lane="web"
)
```

Repeat this for additional sessions. `attackgraph_get_h3retik_workspace`
returns the combined live session/job view, while Sibyl retains evidence after
those sessions expire.

When a session needs more runtime, call
`attackgraph_create_h3retik_extension_receipt`. Funding the returned Base
address does not create a new session. After payment, call
`attackgraph_sync_h3retik_receipt`; the existing session receives the added
minutes/actions and its receipt-issued bearer remains valid through the new
grace deadline.

## Execution loop

1. Create an `autonomous_lab` engagement with an exact target allowlist.
2. Attach one or more H3RETIK sessions to that engagement workspace.
3. Call `attackgraph_request_action` with the command, target, lane, risk, and
   selected session ID.
4. Review the returned request and policy decision.
5. If correct, call `attackgraph_execute_approved_h3retik_job` with the action
   request ID and approval code.
6. Inspect the sanitized evidence returned from Sibyl.

The built-in execution path emits normalized `execution.completed` telemetry.
For an external H3RETIK runner, call `attackgraph_ingest_h3retik_event` with the
bound session ID, job ID, command ID, terminal status, exit code, scoped action
ID, adapter attestation token, and sanitized evidence. Reuse the agent
assertion's `idempotency_key` to
promote that same event instead of creating a duplicate.

Give `ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN` only to the executor adapter, never
to the MCP configurations generated for agent workers. Rotate it if it appears
in a transcript, recording, or client log.

Executor evidence without an ATTACKGRAPH action is retained as `attested`, not
discarded, but it cannot promote a high-impact posture. See
[TELEMETRY_V1.md](TELEMETRY_V1.md) for the full correlation contract.

The approval code is compared server-side and is never persisted. Rotate it
after every demo or engagement.

## Hard boundaries

- Authorized targets only.
- No persistence, service disruption, destructive commands, credential theft,
  data exfiltration, malware, or ransomware.
- `manual_only` and `local_lab` never dispatch to H3RETIK.
- ATTACKGRAPH never submits findings or challenge answers automatically.
