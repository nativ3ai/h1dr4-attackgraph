# 3-minute demo runbook

## 0:00 — The problem

Show two blank agent sessions. Explain that today's red-team agent forgets the
engagement when its context ends, repeats failed work, and loses provenance.

## 0:25 — Open an engagement

Open an `autonomous_lab` engagement for an explicitly owned demo target. Have
the first worker read `attackgraph_get_reporting_contract`, then report one
finding assertion, one failed attempt, and one open hypothesis.

Open **IDENTITY**, create two named MCP workers, and show that each gets a
separate revocable token scoped to this engagement. Do not reveal the token on
the recorded screen.

## 0:55 — The attack brief

Call `attackgraph_get_brief` from one worker. Point out the separation between
confirmed facts, asserted telemetry, open hypotheses, exhausted paths, pending
actions, and exact scope.

## 1:20 — Disposable Kali

Request an `nmap` or `curl` action. Show the policy decision and human approval.
Execute it in the fixed H3RETIK Kali worker. Ingest its result using the same
idempotency key as the assertion: one dashboard event moves from `ASSERTED` to
`VERIFIED`, with a server-generated proof digest.

## 2:00 — Fresh-session recall

Stop the MCP process. Start a new one with the same Sibyl database and operator.
Call `attackgraph_get_brief` without replaying the conversation. Show that the
new agent continues from shared evidence, does not repeat the failed approach,
and that the dashboard still attributes each event to the worker and H3RETIK
session that produced it.

## 2:30 — Make a finding durable

Promote the confirmed finding into a regression check. Finish on the attack
graph: every future agent inherits the engagement's knowledge.

## Backup path

If paid compute is unavailable, replay a saved, clearly labeled H3RETIK fixture.
Do not imply it is a live worker. The persistence and deletion proofs remain
fully live.
