# Validation record

Validated on 2026-08-31 from a non-FileProvider macOS workspace.

## Automated

```text
ruff: all checks passed
pytest: 12 passed
package: sdist and wheel build successfully
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

## MCP transport

A real stdio client opened an engagement, stopped the server, started separate
server processes for subsequent calls, and recovered `MCP-FRESH-001` from the
same Sibyl database. This validates protocol negotiation and fresh-process
recall rather than only direct Python calls.

## Live read-only adapters

The live H1DR4 endpoint returned these matches for `osint`:

```text
h1dr4_osint_capabilities
h1dr4_osint_prepare
h1dr4_osint_agent
```

The live H3RETIK endpoint advertised 33 tools, including compute-window quote,
session-job create/start, job status, and job output. A read-only quote for a
5-minute, 3-action Europe window returned `0.19 USDC`; no terms were accepted,
transaction signed, compute rented, or funds spent during this validation.

## Pending live execution

The paid Kali smoke test remains deliberately pending until the wallet operator
personally accepts the current H3RETIK terms and authorizes the quoted payment.
The integration path is implemented and tested with a mocked lifecycle; it is
not represented as live-paid evidence yet.
