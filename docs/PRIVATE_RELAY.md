# Private workspace relay

The relay is a store-and-forward coordination service, not a hosted Sibyl.
Every authorized operator retains a local Sibyl database and uses the ordinary
local AttackGraph MCP server. AttackGraph synchronizes encrypted workspace
snapshots over HTTPS before reads and after writes.

```text
Codex A -> local MCP -> local Sibyl A -- encrypted snapshots --+
                                                               |
                                                     H1DR4 relay
                                                               |
Codex B -> local MCP -> local Sibyl B -- encrypted snapshots --+
```

## Cryptographic boundary

- One random 256-bit AES-GCM key encrypts a workspace.
- Every device has an Ed25519 signing key.
- Envelope additional authenticated data binds the workspace, event, actor,
  and creation time.
- The relay verifies the ciphertext hash, signature, authenticated actor, role,
  and workspace membership before accepting an event.
- The relay never receives the workspace key or decrypted snapshot.
- A one-use invite wraps the workspace key under a separate random invite
  secret. The relay receives only a hash-derived redemption verifier.

Relay operators can still observe metadata such as event timing, ciphertext
size, opaque workspace identifiers, and membership count. This is not a
metadata-hiding protocol.

## Synchronization contract

The SQLite database is never copied between machines. Each relay event contains
an encrypted `h1dr4.workspace.snapshot.v1` materialization. The receiving client
merges graph records by stable ID, preserves list provenance, prefers newer
updates, and prefers higher assurance when telemetry is promoted from asserted
to attested or verified.

Relay writes are idempotent by event ID. Reusing an event ID with different
ciphertext is rejected. A cursor gives every member deterministic catch-up.

## Enrollment

1. The owner opens an engagement locally.
2. `attackgraph host` creates the relay workspace and publishes the first
   encrypted snapshot.
3. `attackgraph invite` creates a one-use, expiring invite.
4. The second operator runs `attackgraph join` locally and receives the wrapped
   key plus an independent revocable relay credential.
5. Its first pull reconstructs the engagement in its own Sibyl database.

The owner can inspect and revoke membership with `attackgraph members` and
`attackgraph revoke`. Equivalent MCP tools let Codex perform the complete
enrollment flow directly.

Never paste an invite code into a recorded prompt or commit it. Deliver it to
the intended operator over an authenticated private channel.

## Hosted H1DR4 relay

The production client endpoint is:

```text
https://h1dr4.dev/api/v1/attackgraph
```

Set the same local paths in the shell and in the MCP configuration so the CLI
and the connected agent use one Sibyl and one relay identity:

```bash
export ATTACKGRAPH_DB_PATH=/absolute/path/attackgraph/sibyl.db
export ATTACKGRAPH_RELAY_STATE_PATH=/absolute/path/attackgraph/relay.json
export ATTACKGRAPH_RELAY_URL=https://h1dr4.dev/api/v1/attackgraph
```

Creating a new hosted workspace is currently a private-beta operation. The
owner needs a short-lived `ATTACKGRAPH_RELAY_BOOTSTRAP_TOKEN` issued by H1DR4
for the `host` call only. The bootstrap token is not a workspace credential and
must not be sent to collaborators. A collaborator needs only the one-use invite
code; redemption returns an independent, revocable membership credential.

Owner:

```bash
uv run attackgraph host eng-example --name WEB-01
uv run attackgraph invite eng-example --role operator --hours 24
```

Collaborator, on another machine:

```bash
export ATTACKGRAPH_DB_PATH=/absolute/path/friend/sibyl.db
export ATTACKGRAPH_RELAY_STATE_PATH=/absolute/path/friend/relay.json
uv run attackgraph join 'h1dr4-ag1:REDACTED' --name AUTH-02
uv run attackgraph sync eng-example
```

The equivalent MCP tools are
`attackgraph_host_private_workspace`, `attackgraph_create_private_invite`,
`attackgraph_join_private_workspace`,
`attackgraph_sync_private_workspace`,
`attackgraph_private_workspace_members`, and
`attackgraph_revoke_private_workspace_member`. Normal AttackGraph reads pull
before returning a brief and normal writes publish after the local Sibyl
commit, so explicit `sync` is mainly a catch-up and diagnostic control.

## What multiplayer does not share

- H3RETIK wallet, session bearer, and executor-attestation secrets remain local.
- Dashboard passkeys and MCP agent tokens remain device-local identities.
- The relay never receives the SQLite database, workspace key, invite secret,
  target, finding text, loot, command output, or report body in plaintext.
- A workspace can reference several H3RETIK session IDs, but the machines do
  not need to be co-located with either operator.

## Revocation

Revocation immediately blocks future relay reads and writes for the member's
credential. It cannot erase intelligence already decrypted on that member's
device. Production removal must also rotate the workspace key for subsequent
events; historical access remains an inherent property of collaboration.

## Development smoke

Start the in-memory H1DR4 relay fixture from the H1DR4 API checkout:

```bash
npm run dev:attackgraph-relay
```

Then, from this repository:

```bash
uv run python scripts/smoke_private_relay.py
```

The smoke creates two isolated Sibyl databases, joins the second operator,
publishes an exhausted attack path, recalls it from the first database, and
asserts that neither the target nor the path appears in relay-visible JSON.

Run the same receipt against a deployed relay by supplying its URL and a
bootstrap token through the environment:

```bash
ATTACKGRAPH_RELAY_BOOTSTRAP_TOKEN=REDACTED \
uv run python scripts/smoke_private_relay.py \
  --relay https://h1dr4.dev/api/v1/attackgraph
```
