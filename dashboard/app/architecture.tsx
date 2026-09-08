'use client';

import { useEffect, useMemo, useState } from 'react';
import type { IdentitySnapshot, Snapshot } from './model';

type RuntimeMode = 'local' | 'cloud';
type ComponentId = 'operator' | 'virtuals' | 'agent' | 'attackgraph' | 'policy' | 'h1dr4' | 'sibyl' | 'execution' | 'base' | 'dashboard';
type NodePort = 'top' | 'right' | 'bottom' | 'left';
type DocChapterId = 'model' | 'request' | 'ownership' | 'runtime' | 'proof';

type ComponentSpec = {
  id: ComponentId;
  eyebrow: string;
  title: string;
  role: string;
  stores: string;
  boundary: string;
  tone: 'pink' | 'aqua' | 'purple' | 'orange' | 'green' | 'muted';
};

const COMPONENTS: Record<ComponentId, ComponentSpec> = {
  operator: {
    id: 'operator', eyebrow: 'AUTHORITY', title: 'OPERATOR + TEAM', tone: 'pink',
    role: 'Creates the engagement, defines exact scope, invites humans, and issues revocable identities to agent workers.',
    stores: 'Passkeys, memberships and browser sessions live in the local control database.',
    boundary: 'Humans operate the dashboard. Agents do the work through scoped MCP identities.',
  },
  virtuals: {
    id: 'virtuals', eyebrow: 'OPTIONAL ADAPTER', title: 'VIRTUALS / ACP', tone: 'muted',
    role: 'A future distribution and agent-commerce adapter. A Virtuals agent would enter as an ordinary scoped MCP worker.',
    stores: 'No AttackGraph memory, findings or target data belong in Virtuals.',
    boundary: 'Not present in v1. Removing it changes nothing in the core product.',
  },
  agent: {
    id: 'agent', eyebrow: 'REASONING PLANE', title: 'ANY MCP AGENT', tone: 'aqua',
    role: 'Codex, Hermes, Claude, a local model, or another MCP host reads the brief, plans work and reports semantic telemetry.',
    stores: 'The model context is temporary. Durable engagement state belongs to Sibyl.',
    boundary: 'The agent can assert findings, but it cannot self-declare executor proof or a PWNED state.',
  },
  attackgraph: {
    id: 'attackgraph', eyebrow: 'CONTROL PLANE', title: 'H1DR4 ATTACKGRAPH MCP', tone: 'pink',
    role: 'The model-agnostic broker that exposes scope, memory, telemetry, policy, execution and evidence tools.',
    stores: 'No independent engagement database: it reads and writes through Sibyl and the identity control store.',
    boundary: 'Every target is checked against the engagement allowlist before telemetry or execution is accepted.',
  },
  policy: {
    id: 'policy', eyebrow: 'TRUST GATE', title: 'SCOPE + POLICY', tone: 'orange',
    role: 'Evaluates target, lane, risk, destructive patterns, runtime and budget before an active action becomes dispatchable.',
    stores: 'The decision and proposed action become part of the engagement graph.',
    boundary: 'A staged action is not evidence. It cannot change posture until an executor result is correlated.',
  },
  h1dr4: {
    id: 'h1dr4', eyebrow: 'CAPABILITY PLANE', title: 'H1DR4 TOOLS', tone: 'purple',
    role: 'Supplies discoverable OSINT, security and infrastructure capabilities without coupling AttackGraph to a fixed tool catalog.',
    stores: 'Capability descriptions are discovered on demand; engagement truth remains in Sibyl.',
    boundary: 'H1DR4 expands what workers can do. It is not the memory or the execution machine.',
  },
  sibyl: {
    id: 'sibyl', eyebrow: 'MEMORY PLANE', title: 'SIBYL MEMORY', tone: 'green',
    role: 'The shared operational brain: hot graph, cold event history, findings, failed paths, loot, proof and regressions.',
    stores: 'Local default: .attackgraph/sibyl.db, isolated by deterministic operator tenant.',
    boundary: 'Secrets are redacted before persistence. Removing Sibyl destroys fresh-session recall and coordinated state.',
  },
  execution: {
    id: 'execution', eyebrow: 'EXECUTION PLANE', title: 'EXECUTION RUNTIME', tone: 'purple',
    role: 'Runs the bounded command or job selected by the operator and agent.',
    stores: 'Transient command state and output until normalized telemetry is returned to AttackGraph.',
    boundary: 'Execution is replaceable: use the operator machine locally or disposable H3RETIK infrastructure.',
  },
  base: {
    id: 'base', eyebrow: 'SETTLEMENT PLANE', title: 'BASE / USDC', tone: 'orange',
    role: 'Settles H3RETIK compute receipts and unlocks or extends a paid disposable session.',
    stores: 'Payment transaction state only. No targets, findings, credentials, prompts or attack graph.',
    boundary: 'Base is required for paid H3RETIK compute, not for local execution or Sibyl memory.',
  },
  dashboard: {
    id: 'dashboard', eyebrow: 'OPERATOR VIEW', title: 'ATTACKGRAPH DASHBOARD', tone: 'pink',
    role: 'Projects Sibyl into the operation brief, target building, live feed, worker roster, attacks, loot and verified posture.',
    stores: 'The browser keeps only device-local view preferences and an authenticated browser session.',
    boundary: 'The dashboard displays state. It is not the system of record and does not execute attacks.',
  },
};

const FLOW = [
  { id: 'connect', label: 'CONNECT', component: 'operator' as ComponentId, title: 'Create the authorized workspace', input: 'Target + scope + mode + lanes', output: 'Engagement ID + agent memberships', guard: 'An agent identity can access only engagements where it has membership.' },
  { id: 'recall', label: 'RECALL', component: 'sibyl' as ComponentId, title: 'Load the shared operational brain', input: 'attackgraph_get_brief', output: 'Confirmed evidence + hypotheses + exhausted paths + pending work', guard: 'A fresh model session receives durable state without replaying the old conversation.' },
  { id: 'plan', label: 'PLAN', component: 'policy' as ComponentId, title: 'Convert reasoning into a scoped action', input: 'Target + lane + command + risk + budget', output: 'Recorded action + policy decision', guard: 'A planned or queued job is never treated as successful evidence.' },
  { id: 'execute', label: 'EXECUTE', component: 'execution' as ComponentId, title: 'Run in the selected execution plane', input: 'Approved action specification', output: 'Status + exit code + sanitized output', guard: 'Local and cloud execution are interchangeable; the engagement memory is not.' },
  { id: 'report', label: 'REPORT', component: 'attackgraph' as ComponentId, title: 'Normalize activity into telemetry v1', input: 'Event type + meaning + entities + relationships', output: 'Asserted semantic event in Sibyl', guard: 'The model supplies meaning, not proof authority.' },
  { id: 'promote', label: 'PROMOTE', component: 'sibyl' as ComponentId, title: 'Correlate evidence without duplicating it', input: 'Same idempotency key + executor attestation', output: 'ASSERTED → ATTESTED → VERIFIED', guard: 'Verified requires authenticated executor evidence tied to the scoped action and target.' },
  { id: 'render', label: 'RENDER', component: 'dashboard' as ComponentId, title: 'Project memory into operator state', input: 'Sibyl graph + journal + proof chain', output: 'Rooms + live feed + loot + WHY THIS STATE', guard: 'Free-form labels cannot set PWNED; posture is derived from qualifying evidence.' },
];

const HIERARCHY = [
  { level: 0, label: 'OPERATOR TENANT', meta: 'ISOLATION BOUNDARY', tone: 'pink' },
  { level: 1, label: 'ENGAGEMENT', meta: 'TARGET + SCOPE + MODE', tone: 'aqua' },
  { level: 2, label: 'IDENTITY CONTROL', meta: 'PASSKEYS / AGENTS / MEMBERSHIPS', tone: 'purple' },
  { level: 2, label: 'H3RETIK SESSION BINDINGS', meta: 'COMPUTE LENSES, NOT THE TARGET', tone: 'purple' },
  { level: 2, label: 'SIBYL GRAPH', meta: 'DURABLE SHARED BRAIN', tone: 'green' },
  { level: 3, label: 'TELEMETRY EVENT', meta: 'ACTOR + TARGET + OUTCOME', tone: 'green' },
  { level: 4, label: 'ENTITIES + RELATIONSHIPS', meta: 'WHAT CONNECTS TO WHAT', tone: 'aqua' },
  { level: 4, label: 'PROOF + ASSURANCE', meta: 'ASSERTED / ATTESTED / VERIFIED', tone: 'orange' },
  { level: 3, label: 'MATERIALIZED RECORDS', meta: 'FINDINGS / ATTEMPTS / LOOT / CHECKPOINTS', tone: 'pink' },
  { level: 3, label: 'JOURNAL EVENTS', meta: 'REAL-TIME FEED + FRESH RECALL', tone: 'purple' },
];

const COMPARISON = [
  ['EXECUTION', 'Operator machine or local container', 'Disposable scoped H3RETIK machine'],
  ['MEMORY', 'Same local Sibyl engagement', 'Same local Sibyl engagement'],
  ['ISOLATION', 'Depends on operator environment', 'Ephemeral compute boundary'],
  ['PAYMENT', 'None', 'Receipt settled on Base in USDC/H1DR4'],
  ['TOOLS', 'Anything installed locally', 'Lean image + tools loaded for the session'],
  ['PROOF', 'Agent assertion unless a trusted runner attests', 'Session/job/command evidence can be attested'],
  ['CLEANUP', 'Operator responsibility', 'Runtime expires and is destroyed'],
  ['BEST FOR', 'Fast trusted labs and development', 'Risky tooling, clean demos and parallel workers'],
];

const DOC_CHAPTERS: Array<{
  id: DocChapterId;
  nav: string;
  title: string;
  lead: string;
  invariant: string;
  points: Array<{ label: string; title: string; body: string }>;
}> = [
  {
    id: 'model', nav: 'MENTAL MODEL', title: 'Five parts, one engagement.',
    lead: 'AttackGraph is the control surface around an authorized red-team engagement. Agents may come and go; the engagement identity and Sibyl memory remain.',
    invariant: 'The target is the engagement. An H3RETIK machine is only a temporary worker attached to it.',
    points: [
      { label: 'AUTHORITY', title: 'Operator + team', body: 'Create scope, invite people and issue revocable identities to agent workers.' },
      { label: 'CONTROL', title: 'AttackGraph MCP', body: 'Checks identity and scope, exposes tools, records actions and routes bounded execution.' },
      { label: 'MEMORY', title: 'Sibyl', body: 'Keeps the durable graph, event history, findings, failed paths, loot and proof across fresh agents.' },
      { label: 'COMPUTE', title: 'Local or H3RETIK', body: 'Runs the job. It can be replaced without replacing the engagement or its memory.' },
    ],
  },
  {
    id: 'request', nav: 'REQUEST PATH', title: 'What happens when an agent acts.',
    lead: 'A command is never sent straight from a model to a machine. It moves through a typed, scoped path and returns as normalized evidence.',
    invariant: 'Planning, execution and proof are distinct events. A requested action is never evidence of success.',
    points: [
      { label: '01 / RECALL', title: 'Read the brief', body: 'The agent loads confirmed facts, hypotheses, failed attempts and pending work from Sibyl.' },
      { label: '02 / AUTHORIZE', title: 'Check the action', body: 'AttackGraph binds the proposed command to agent identity, engagement scope, lane and budget.' },
      { label: '03 / EXECUTE', title: 'Run one bounded job', body: 'The selected local or H3RETIK runtime produces status, output and executor metadata.' },
      { label: '04 / INGEST', title: 'Normalize the result', body: 'AttackGraph redacts the return, correlates proof, writes Sibyl and projects the new state to the dashboard.' },
    ],
  },
  {
    id: 'ownership', nav: 'DATA OWNERSHIP', title: 'Every datum has one proper home.',
    lead: 'The system avoids a second hidden source of truth. Durable operational truth belongs to Sibyl; short-lived execution state stays with the runtime.',
    invariant: 'Targets, prompts, findings, credentials and attack history never belong on Base or inside Virtuals.',
    points: [
      { label: 'IDENTITY STORE', title: 'Who may enter', body: 'Passkeys, team membership, agent credentials and revocation state.' },
      { label: 'SIBYL', title: 'What the operation knows', body: 'Redacted telemetry, entities, relationships, attempts, proof, provenance and derived posture.' },
      { label: 'RUNTIME', title: 'What the current job needs', body: 'Transient process state, command output and artifacts until their safe result is ingested.' },
      { label: 'BASE', title: 'What cloud compute cost', body: 'Payment and receipt state only. It unlocks compute but never stores attack data.' },
    ],
  },
  {
    id: 'runtime', nav: 'LOCAL VS CLOUD', title: 'Same brain, different execution boundary.',
    lead: 'Changing the execution lens does not create a different product. The MCP contract, engagement ID, Sibyl records and operator view remain the same.',
    invariant: 'H3RETIK improves isolation, disposability and executor evidence; it does not replace Sibyl or the dashboard.',
    points: [
      { label: 'LOCAL', title: 'Fast trusted work', body: 'Use the operator machine or a local container. No payment rail; cleanup is the operator’s responsibility.' },
      { label: 'H3RETIK', title: 'Disposable scoped compute', body: 'Rent a short-lived machine, load the needed tool profile, run the bounded job and destroy the runtime.' },
      { label: 'SETTLEMENT', title: 'Base unlocks the session', body: 'A USDC receipt authorizes paid remote capacity. No engagement memory is written onchain.' },
      { label: 'RETURN', title: 'Evidence rejoins the graph', body: 'Sanitized job facts flow back through AttackGraph into the same Sibyl engagement.' },
    ],
  },
  {
    id: 'proof', nav: 'EVIDENCE + STATE', title: 'How a report becomes trusted posture.',
    lead: 'Agents provide semantic meaning, but high-impact dashboard state is derived only after that meaning correlates with authenticated executor evidence.',
    invariant: 'An agent cannot write PWNED directly. The dashboard derives state from qualifying, traceable Sibyl records.',
    points: [
      { label: 'ASSERTED', title: 'The agent reports meaning', body: 'Useful for coordination and hypotheses, but insufficient for a high-impact state change.' },
      { label: 'ATTESTED', title: 'Executor facts exist', body: 'Authenticated runtime output is present, but full action and target correlation is incomplete.' },
      { label: 'VERIFIED', title: 'Proof is correlated', body: 'Target, scoped action, session, outcome and proof reference agree under one idempotency key.' },
      { label: 'DERIVED', title: 'The dashboard explains why', body: 'Posture is computed deterministically and links back through WHY THIS STATE to supporting records.' },
    ],
  },
];

export default function ArchitectureView({ snapshot, identity }: { snapshot: Snapshot; identity: IdentitySnapshot }) {
  const [mode, setMode] = useState<RuntimeMode>('cloud');
  const [selected, setSelected] = useState<ComponentId>('attackgraph');
  const [step, setStep] = useState(0);
  const [running, setRunning] = useState(false);
  const [chapter, setChapter] = useState<DocChapterId>('model');

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setStep((current) => (current + 1) % FLOW.length), 1250);
    return () => window.clearInterval(timer);
  }, [running]);

  const execution = useMemo<ComponentSpec>(() => mode === 'cloud' ? {
    ...COMPONENTS.execution,
    title: 'H3RETIK CLOUD SESSION',
    role: 'Agent-native command compute: a paid, disposable, scoped machine rented by action quota or short compute window.',
    stores: 'Transient commands, logs and artifacts until sanitized results are ingested into Sibyl.',
    boundary: 'The session is execution capacity, not an engagement and not the long-term memory.',
  } : {
    ...COMPONENTS.execution,
    title: 'LOCAL RUNNER',
    role: 'Runs authorized work on the operator workstation, local Kali container, or another trusted local sandbox.',
    stores: 'Local process and filesystem state. AttackGraph still records normalized results in Sibyl.',
    boundary: 'No Base payment and no cloud isolation. Cleanup and tool hygiene remain operator responsibilities.',
  }, [mode]);
  const selectedSpec = selected === 'execution' ? execution : COMPONENTS[selected];
  const activeFlow = FLOW[step];
  const activeChapter = DOC_CHAPTERS.find((item) => item.id === chapter) ?? DOC_CHAPTERS[0];
  const liveWorkers = identity.agents.filter((agent) => agent.status === 'active').length;

  const choose = (id: ComponentId) => {
    setSelected(id);
    const matchingStep = FLOW.findIndex((item) => item.component === id);
    if (matchingStep >= 0) setStep(matchingStep);
  };

  return <div className={`architecture-deck runtime-${mode}`}>
    <header className="architecture-heading">
      <div>
        <span>06 / INTERACTIVE SYSTEM MANUAL</span>
        <h2>One brain. Replaceable workers.</h2>
        <p>Click any system block or run the lifecycle to inspect ownership, data flow and trust boundaries.</p>
      </div>
      <div className="runtime-switch" aria-label="Execution runtime">
        <span>EXECUTION LENS</span>
        <div>
          <button type="button" aria-pressed={mode === 'local'} onClick={() => { setMode('local'); setSelected('execution'); }}>LOCAL</button>
          <button type="button" aria-pressed={mode === 'cloud'} onClick={() => { setMode('cloud'); setSelected('execution'); }}>H3RETIK CLOUD</button>
        </div>
      </div>
    </header>

    <section className="architecture-live-strip" aria-label="Current system state">
      <div><span>SIBYL</span><strong>LIVE</strong><small>{snapshot.memory.event_count} JOURNAL EVENTS</small></div>
      <div><span>GRAPH</span><strong>{snapshot.stats.nodes}</strong><small>{snapshot.stats.relationships || 0} RELATIONSHIPS</small></div>
      <div><span>WORKERS</span><strong>{liveWorkers}</strong><small>{identity.agents.length} REGISTERED</small></div>
      <div><span>H3 SESSIONS</span><strong>{identity.h3retik_sessions.length}</strong><small>BOUND TO ENGAGEMENT</small></div>
      <div><span>RUNTIME</span><strong>{mode === 'cloud' ? 'REMOTE' : 'LOCAL'}</strong><small>{mode === 'cloud' ? 'BASE-SETTLED' : 'NO PAYMENT RAIL'}</small></div>
    </section>

    <section className="architecture-system-section">
      <div className="architecture-system-map" aria-label="AttackGraph component map">
        <div className="topology-legend"><span><i />CORE</span><span><i />REPLACEABLE</span><span><i />OPTIONAL</span></div>

        <section className="topology-band entry-band">
          <header><b>01</b><span>ENTRY / WHO CAN PARTICIPATE</span></header>
          <div className="topology-triple">
            <SystemNode spec={COMPONENTS.operator} selected={selected === 'operator'} ports={['right']} onClick={() => choose('operator')} />
            <FlowLink label="ISSUES SCOPED ID" />
            <SystemNode spec={COMPONENTS.agent} selected={selected === 'agent'} ports={['left', 'right', 'bottom']} onClick={() => choose('agent')} />
            <FlowLink label="OPTIONAL ORIGIN" reverse optional />
            <SystemNode spec={COMPONENTS.virtuals} selected={selected === 'virtuals'} ports={['left']} optional onClick={() => choose('virtuals')} />
          </div>
        </section>

        <VerticalLink label="TYPED MCP CALLS" />

        <section className="topology-band control-band">
          <header><b>02</b><span>ORCHESTRATION / ONE GOVERNING CONTROL PLANE</span></header>
          <div className="topology-triple">
            <SystemNode spec={COMPONENTS.policy} selected={selected === 'policy'} ports={['right']} onClick={() => choose('policy')} />
            <FlowLink label="SCOPE DECISION" />
            <SystemNode spec={COMPONENTS.attackgraph} selected={selected === 'attackgraph'} ports={['top', 'left', 'right', 'bottom']} featured onClick={() => choose('attackgraph')} />
            <FlowLink label="CAPABILITY DISCOVERY" reverse />
            <SystemNode spec={COMPONENTS.h1dr4} selected={selected === 'h1dr4'} ports={['left']} onClick={() => choose('h1dr4')} />
          </div>
        </section>

        <div className="topology-fork" aria-hidden="true"><span>WRITE SHARED STATE ↓</span><i /><b>DISPATCH ↓ / RESULT ↑</b></div>

        <section className="topology-band operation-band">
          <header><b>03</b><span>OPERATION / DURABLE BRAIN + REPLACEABLE RUNTIME</span></header>
          <div className="topology-double">
            <SystemNode spec={COMPONENTS.sibyl} selected={selected === 'sibyl'} ports={['top', 'bottom']} featured onClick={() => choose('sibyl')} />
            <div className="plane-separator"><i /><span>NO DIRECT MEMORY WRITE</span><i /></div>
            <SystemNode spec={execution} selected={selected === 'execution'} ports={['top', 'bottom']} featured onClick={() => choose('execution')} />
          </div>
        </section>

        <div className="topology-output-links" aria-hidden="true"><span>PROJECT OPERATOR VIEW ↓</span><span>{mode === 'cloud' ? '↑ RECEIPT UNLOCKS SESSION' : 'PAYMENT LAYER BYPASSED'}</span></div>

        <section className="topology-band output-band">
          <header><b>04</b><span>OUTPUT / WHAT HUMANS SEE + WHAT CLOUD COMPUTE COSTS</span></header>
          <div className="topology-double outputs">
            <SystemNode spec={COMPONENTS.dashboard} selected={selected === 'dashboard'} ports={['top']} featured onClick={() => choose('dashboard')} />
            <div className="output-separator"><i /><span>NO ATTACK DATA ONCHAIN</span><i /></div>
            <SystemNode spec={COMPONENTS.base} selected={selected === 'base'} ports={['top']} featured inactive={mode === 'local'} onClick={() => choose('base')} />
          </div>
        </section>
      </div>

      <aside className={`architecture-inspector tone-${selectedSpec.tone}`}>
        <div className="inspector-index">COMPONENT::{String(Object.keys(COMPONENTS).indexOf(selected) + 1).padStart(2, '0')}</div>
        <span>{selectedSpec.eyebrow}</span>
        <h3>{selectedSpec.title}</h3>
        <dl>
          <div><dt>ROLE</dt><dd>{selectedSpec.role}</dd></div>
          <div><dt>DATA</dt><dd>{selectedSpec.stores}</dd></div>
          <div><dt>HARD BOUNDARY</dt><dd>{selectedSpec.boundary}</dd></div>
        </dl>
        <footer><i /><span>{selected === 'virtuals' ? 'NOT IN CORE V1' : selected === 'base' && mode === 'local' ? 'BYPASSED IN LOCAL MODE' : 'ACTIVE ARCHITECTURE COMPONENT'}</span></footer>
      </aside>
    </section>

    <section className="architecture-reader" aria-label="Architecture documentation">
      <aside className="docs-index">
        <span>DOCUMENTATION / START HERE</span>
        <h3>Read the system.</h3>
        <p>The graph shows where components sit. These five short chapters explain responsibility, flow and trust.</p>
        <nav aria-label="Architecture documentation chapters">
          {DOC_CHAPTERS.map((item, index) => <button type="button" aria-pressed={chapter === item.id} onClick={() => setChapter(item.id)} key={item.id}><b>{String(index + 1).padStart(2, '0')}</b><span>{item.nav}</span><i>→</i></button>)}
        </nav>
        <a className="docs-full-link" href="/docs">OPEN OPERATOR + DEV DOCS <b>↗</b></a>
      </aside>
      <article className="docs-chapter" aria-live="polite">
        <header>
          <span>CHAPTER {String(DOC_CHAPTERS.indexOf(activeChapter) + 1).padStart(2, '0')} / {activeChapter.nav}</span>
          <h3>{activeChapter.title}</h3>
          <p>{activeChapter.lead}</p>
        </header>
        <div className="docs-points">
          {activeChapter.points.map((point, index) => <section key={point.label}><b>{String(index + 1).padStart(2, '0')}</b><div><span>{point.label}</span><h4>{point.title}</h4><p>{point.body}</p></div></section>)}
        </div>
        <footer><span>NON-NEGOTIABLE</span><strong>{activeChapter.invariant}</strong></footer>
      </article>
    </section>

    <section className="architecture-flow-section">
      <header>
        <div><span>ATTACK LIFECYCLE</span><h3>Follow one action through the stack</h3></div>
        <button type="button" aria-pressed={running} onClick={() => setRunning((current) => !current)}>{running ? 'II PAUSE FLOW' : '▶ RUN FLOW'}</button>
      </header>
      <div className="flow-stepper" role="tablist" aria-label="Attack lifecycle steps">
        {FLOW.map((item, index) => <button type="button" role="tab" aria-selected={step === index} className={step === index ? 'active' : index < step ? 'passed' : ''} onClick={() => { setStep(index); setRunning(false); setSelected(item.component); }} key={item.id}><b>{String(index + 1).padStart(2, '0')}</b><span>{item.label}</span><i /></button>)}
      </div>
      <div className="flow-readout">
        <div className="flow-number">{String(step + 1).padStart(2, '0')}<small>/ {String(FLOW.length).padStart(2, '0')}</small></div>
        <div className="flow-copy"><span>{activeFlow.label}::{COMPONENTS[activeFlow.component].eyebrow}</span><h4>{activeFlow.title}</h4><p>{activeFlow.guard}</p></div>
        <dl><div><dt>INPUT</dt><dd>{activeFlow.input}</dd></div><div><dt>OUTPUT</dt><dd>{activeFlow.output}</dd></div></dl>
      </div>
    </section>

    <div className="architecture-knowledge-grid">
      <section className="architecture-hierarchy">
        <header><span>DATA HIERARCHY</span><strong>WHO OWNS WHAT</strong></header>
        <div>{HIERARCHY.map((item, index) => <div className={`hierarchy-row level-${item.level} tone-${item.tone}`} key={`${item.label}-${index}`}><i /><b>{item.label}</b><span>{item.meta}</span></div>)}</div>
      </section>

      <section className="trust-ladder">
        <header><span>ASSURANCE LADDER</span><strong>HOW PWNED BECOMES TRUE</strong></header>
        <div className="trust-level asserted"><b>01</b><div><strong>ASSERTED</strong><p>An agent reports semantic meaning. Useful for coordination, never enough for high-impact posture.</p></div></div>
        <div className="trust-arrow">SAME IDEMPOTENCY KEY + EXECUTOR EVIDENCE ↓</div>
        <div className="trust-level attested"><b>02</b><div><strong>ATTESTED</strong><p>Authenticated executor facts exist, but no scoped AttackGraph action correlation is complete.</p></div></div>
        <div className="trust-arrow">TARGET + ACTION + SESSION + SUCCESS CORRELATE ↓</div>
        <div className="trust-level verified"><b>03</b><div><strong>VERIFIED</strong><p>Proof is bound to the authorized action. Sibyl may now promote the same record and posture.</p></div></div>
      </section>
    </div>

    <section className="architecture-compare">
      <header><div><span>RUNTIME COMPARISON</span><h3>Same brain, different execution boundary</h3></div><strong>{mode === 'cloud' ? 'H3RETIK LENS ACTIVE' : 'LOCAL LENS ACTIVE'}</strong></header>
      <div className="compare-table" role="table" aria-label="Local and H3RETIK runtime comparison">
        <div className="compare-row head" role="row"><b role="columnheader">LAYER</b><strong role="columnheader">LOCAL</strong><strong role="columnheader">H3RETIK CLOUD</strong></div>
        {COMPARISON.map(([label, local, cloud]) => <div className={`compare-row ${mode === 'cloud' ? 'cloud-active' : 'local-active'}`} role="row" key={label}><b role="cell">{label}</b><span role="cell">{local}</span><span role="cell">{cloud}</span></div>)}
      </div>
    </section>

    <section className="dependency-test">
      <header><span>DEPENDENCY TEST</span><h3>What actually breaks if a layer disappears?</h3></header>
      <div>
        <article className="critical"><span>REMOVE SIBYL</span><strong>THE PRODUCT BREAKS</strong><p>Fresh agents forget evidence and failed paths. Shared graph, provenance and durable posture disappear.</p></article>
        <article><span>REMOVE H3RETIK</span><strong>LOCAL MODE STILL WORKS</strong><p>You lose disposable cloud isolation and proof-rich remote jobs, not the MCP brain or dashboard.</p></article>
        <article><span>REMOVE BASE</span><strong>CLOUD RENTAL STOPS</strong><p>Paid H3RETIK sessions cannot unlock. Local execution and all existing Sibyl memory remain usable.</p></article>
        <article className="optional"><span>REMOVE VIRTUALS</span><strong>NOTHING CORE CHANGES</strong><p>Virtuals may distribute the service later. It is not execution, memory, identity or evidence authority.</p></article>
      </div>
    </section>

    <footer className="architecture-doctrine"><span>CORE DOCTRINE</span><strong>H3RETIK COMPUTES. SIBYL REMEMBERS. ATTACKGRAPH GOVERNS. THE AGENT REASONS.</strong><small>Base settles remote compute. Virtuals remains an optional market adapter.</small></footer>
  </div>;
}

function SystemNode({ spec, selected, ports = [], featured = false, optional = false, inactive = false, onClick }: { spec: ComponentSpec; selected: boolean; ports?: NodePort[]; featured?: boolean; optional?: boolean; inactive?: boolean; onClick: () => void }) {
  return <button type="button" className={`system-node tone-${spec.tone} ${selected ? 'selected' : ''} ${featured ? 'featured' : ''} ${optional ? 'optional' : ''} ${inactive ? 'inactive' : ''}`} aria-pressed={selected} onClick={onClick}><span>{spec.eyebrow}</span><strong>{spec.title}</strong><small>{inactive ? 'BYPASSED' : optional ? 'NOT CORE V1' : 'SELECT TO INSPECT'}</small><i />{ports.map((port) => <em className={`node-port port-${port}`} aria-hidden="true" key={port} />)}</button>;
}

function FlowLink({ label, reverse = false, optional = false }: { label: string; reverse?: boolean; optional?: boolean }) { return <div className={`horizontal-flow ${reverse ? 'reverse' : ''} ${optional ? 'optional' : ''}`}><i /><span>{label}</span><b>{reverse ? '←' : '→'}</b></div>; }
function VerticalLink({ label }: { label: string }) { return <div className="vertical-flow"><i /><span>{label}</span><b>↓</b></div>; }
