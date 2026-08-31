# 3-minute demo runbook

## 0:00 — The problem

Show two blank agent sessions. Explain that today's red-team agent forgets the
engagement when its context ends, repeats failed work, and loses provenance.

## 0:25 — Open an engagement

Open an `autonomous_lab` engagement for an explicitly owned demo target. Record
one observation, one failed attempt, and one open hypothesis.

## 0:55 — The attack brief

Call `attackgraph_get_brief`. Point out the separation between confirmed facts,
open hypotheses, exhausted paths, pending actions, and exact scope.

## 1:20 — Disposable Kali

Request an `nmap` or `curl` action. Show the policy decision and human approval.
Execute it in the fixed H3RETIK Kali worker. Ingest the result as evidence.

## 2:00 — Fresh-session recall

Stop the MCP process. Start a new one with the same Sibyl database and operator.
Call `attackgraph_get_brief` without replaying the conversation. Show that the
new agent continues from the evidence and does not repeat the failed approach.

## 2:30 — Make a finding durable

Promote the confirmed finding into a regression check. Finish on the attack
graph: every future agent inherits the engagement's knowledge.

## Backup path

If paid compute is unavailable, replay a saved, clearly labeled H3RETIK fixture.
Do not imply it is a live worker. The persistence and deletion proofs remain
fully live.
