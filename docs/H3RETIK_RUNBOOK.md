# H3RETIK operator runbook

H3RETIK runs commands only in an existing, paid, disposable session. Provisioning
is intentionally outside the MCP server because accepting legal terms and
authorizing payment are human decisions.

## One-time operator setup

1. Read the current terms: `h3retik-cloud tos status`.
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
uv run h1dr4-attackgraph
```

Do not put these values in `.env` if that file could be copied or shared.

## Execution loop

1. Create an `autonomous_lab` engagement with an exact target allowlist.
2. Call `attackgraph_request_action` with the command, target, lane, and risk.
3. Review the returned request and policy decision.
4. If correct, call `attackgraph_execute_approved_h3retik_job` with the action
   request ID and approval code.
5. Inspect the sanitized evidence returned from Sibyl.

The approval code is compared server-side and is never persisted. Rotate it
after every demo or engagement.

## Hard boundaries

- Authorized targets only.
- No persistence, service disruption, destructive commands, credential theft,
  data exfiltration, malware, or ransomware.
- `manual_only` and `local_lab` never dispatch to H3RETIK.
- ATTACKGRAPH never submits findings or challenge answers automatically.
