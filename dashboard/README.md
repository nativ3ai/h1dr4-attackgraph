# ATTACKGRAPH dashboard

The dashboard is the local human view over the same Sibyl database used by the
MCP server. It is intentionally read-only: agents write through the scoped MCP
tools, while operators inspect topology, evidence, exhausted paths, pending
actions, and regressions here.

From the repository root:

```bash
./scripts/run-dashboard.sh
```

The launcher binds the API to `127.0.0.1:7784` and the interface to
`localhost:3000`. Set `ATTACKGRAPH_DB_PATH` and `ATTACKGRAPH_OPERATOR_ID` before
launching to inspect a different isolated Sibyl tenant.

Validation:

```bash
npm --prefix dashboard run lint
npm --prefix dashboard run build
uv run pytest tests/test_dashboard.py
```
