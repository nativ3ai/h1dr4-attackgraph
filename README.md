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
MCP agent
   │  observations, attempts, action plans
   ▼
H1DR4 ATTACKGRAPH ─── Sibyl Memory
   │                  hot: target graph + current state
   │                  cold: append-only evidence and attempts
   │
   ├── H1DR4 MCP discovery (capabilities)
   └── H3RETIK (human-approved disposable Kali execution)
```

The output is not a wall of notes. `attackgraph_get_brief` returns a compact,
structured handoff: confirmed facts, open hypotheses, exhausted paths, pending
actions, regression checks, and evidence provenance. A fresh agent session can
continue where the previous one stopped.

## Safety modes

| Mode | Intended use | Command behavior |
|---|---|---|
| `manual_only` | Gray Swan and human-assisted arenas | Records plans; never dispatches |
| `local_lab` | Human-operated local targets | Records plans for a local runner |
| `autonomous_lab` | Owned/authorized sandbox targets | H3RETIK dispatch only after human approval |

Every action is checked against an exact target allowlist and allowed execution
lanes. Destructive commands are denied. ATTACKGRAPH never accepts H3RETIK terms,
buys compute, or submits arena answers on the user's behalf.

## Quick start

Requirements: Python 3.11+ and `uv`.

```bash
git clone https://github.com/nativ3ai/h1dr4-attackgraph
cd h1dr4-attackgraph
uv sync --extra dev
cp .env.example .env
uv run h1dr4-attackgraph
```

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
2. `attackgraph_record_observation` and `attackgraph_record_attempt`
3. `attackgraph_get_brief` whenever the agent needs a compact state refresh
4. `attackgraph_request_action` before any active test
5. `attackgraph_create_regression` after a finding is confirmed

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

1. The agent drafts a command with `attackgraph_request_action`.
2. ATTACKGRAPH checks mode, exact target, lane, risk, and destructive patterns.
3. A human supplies the server-side approval code.
4. The adapter creates and starts a scoped job in the existing H3RETIK session.
5. Sanitized output returns to Sibyl as evidence and updates the graph.

Credentials and approval codes are environment-only. They are never returned by
an MCP tool or written to Sibyl. See [docs/H3RETIK_RUNBOOK.md](docs/H3RETIK_RUNBOOK.md).

## H1DR4 integration

`attackgraph_discover_h1dr4_tools` reads the live H1DR4 MCP capability list and
filters it by keyword. This lets the connected agent discover useful H1DR4 tools
without hard-coding a rapidly changing catalog.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest
```

See [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md) for the hackathon demo and
[PRIOR_WORK.md](PRIOR_WORK.md) for the build-window disclosure.

## Status

Hackathon prototype. Use only on systems you own or are explicitly authorized
to test. The server does not make authorization decisions for you.

MIT License.

