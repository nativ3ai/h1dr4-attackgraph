'use client';

import Image from 'next/image';
import Link from 'next/link';
import { useEffect, useState } from 'react';

const DOC_NAV = [
  { group: 'Fundamentals', items: [['overview', 'System overview'], ['request-path', 'Request lifecycle']] },
  { group: 'Use AttackGraph', items: [['quickstart', 'Local quick start'], ['mcp', 'MCP API'], ['telemetry', 'Telemetry contract']] },
  { group: 'Operate', items: [['h3retik', 'H3RETIK execution'], ['security', 'Security model']] },
  { group: 'Contribute', items: [['development', 'Development']] },
] as const;

const FLAT_NAV = DOC_NAV.flatMap((group) => group.items);

const MCP_TOOLS = [
  ['Read', 'attackgraph_list_engagements', 'List engagements visible to the current operator or scoped agent.'],
  ['Read', 'attackgraph_get_brief', 'Return the compact fresh-session handoff: facts, hypotheses, exhausted paths, actions and regressions.'],
  ['Read', 'attackgraph_get_context', 'Return the complete hot graph and recent append-only Sibyl events.'],
  ['Read', 'attackgraph_get_reporting_contract', 'Return Telemetry v1 enums, required fields and assurance rules.'],
  ['Write', 'attackgraph_open_engagement', 'Create an authorized target, mode, allowlist, lanes and rules.'],
  ['Write', 'attackgraph_report_event', 'Submit one typed semantic assertion with a stable idempotency key.'],
  ['Write', 'attackgraph_record_hypothesis', 'Retain an open, confirmed or rejected hypothesis.'],
  ['Write', 'attackgraph_record_attempt', 'Retain a tested or exhausted path so later workers do not repeat it.'],
  ['Policy', 'attackgraph_request_action', 'Validate and record a proposed active action. This call does not execute it.'],
  ['Write', 'attackgraph_create_regression', 'Turn a verified finding into a durable future check.'],
  ['Discover', 'attackgraph_discover_h1dr4_tools', 'Search the live H1DR4 MCP capability catalog by keyword.'],
  ['H3RETIK', 'attackgraph_h3retik_capabilities', 'Read execution capabilities without accepting terms or spending funds.'],
  ['H3RETIK', 'attackgraph_h3retik_quote', 'Read a compute-window quote without purchasing it.'],
  ['H3RETIK', 'attackgraph_list_h3retik_sessions', 'List disposable sessions bound to the engagement.'],
  ['Gated', 'attackgraph_execute_approved_h3retik_job', 'Run one pre-scoped action after server-side approval.'],
  ['Adapter', 'attackgraph_ingest_h3retik_event', 'Authenticate executor facts, compute a proof digest and promote matching telemetry.'],
  ['Adapter', 'attackgraph_ingest_h3retik_result', 'Import a sanitized external job result against a scoped action.'],
] as const;

const EVENTS = [
  ['execution.started', 'A bounded command or job began.'],
  ['execution.completed', 'The command terminated with a status and sanitized outcome.'],
  ['attempt.completed', 'An attack path was tested and may now be marked exhausted.'],
  ['finding.observed', 'A possible issue has useful evidence but is not yet established.'],
  ['finding.confirmed', 'Evidence establishes a finding; executor correlation may still be pending.'],
  ['loot.discovered', 'An artifact or access-material reference was collected and sealed.'],
  ['checkpoint.written', 'A phase, worker or session is ending and must hand state forward.'],
] as const;

const ENVIRONMENT = [
  ['ATTACKGRAPH_DB_PATH', '.attackgraph/sibyl.db', 'Durable Sibyl memory database.'],
  ['ATTACKGRAPH_CONTROL_DB_PATH', '.attackgraph/control.db', 'Passkeys, memberships, agents and session bindings.'],
  ['ATTACKGRAPH_OPERATOR_ID', 'local-operator', 'Tenant isolation key.'],
  ['ATTACKGRAPH_AUTH_MODE', 'optional', 'Set to passkey to require authentication.'],
  ['ATTACKGRAPH_AGENT_TOKEN', 'generated', 'One revocable agent identity, shown once by the dashboard.'],
  ['ATTACKGRAPH_EXECUTION_APPROVAL_CODE', 'operator secret', 'Gate for built-in H3RETIK dispatch.'],
  ['ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN', 'adapter secret', 'Credential for authenticated executor intake.'],
] as const;

function CodeBlock({ label, children }: { label: string; children: string }) {
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'blocked'>('idle');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(children);
      setCopyState('copied');
    } catch {
      setCopyState('blocked');
    }
    window.setTimeout(() => setCopyState('idle'), 1400);
  };
  const labelText = copyState === 'copied' ? 'Copied' : copyState === 'blocked' ? 'Select text' : 'Copy';
  return <figure className="manual-code"><figcaption><span>{label}</span><button type="button" onClick={() => void copy()}>{labelText}</button></figcaption><pre><code>{children}</code></pre></figure>;
}

function SectionHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children: React.ReactNode }) {
  return <header className="manual-section-heading"><span>{eyebrow}</span><h2>{title}</h2><p>{children}</p></header>;
}

export default function DocsPage() {
  const [activeSection, setActiveSection] = useState('overview');

  useEffect(() => {
    const root = document.querySelector('.manual-shell');
    if (!(root instanceof HTMLElement)) return;
    const sections = FLAT_NAV.map(([id]) => document.getElementById(id)).filter((item): item is HTMLElement => Boolean(item));
    let frame = 0;
    const update = () => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(() => {
        const rootRect = root.getBoundingClientRect();
        const readingLine = rootRect.top + Math.min(320, rootRect.height * 0.32);
        const section = sections.find((candidate) => {
          const rect = candidate.getBoundingClientRect();
          return rect.top <= readingLine && rect.bottom > readingLine;
        });
        if (section) setActiveSection(section.id);
      });
    };
    root.addEventListener('scroll', update, { passive: true });
    update();
    return () => {
      root.removeEventListener('scroll', update);
      window.cancelAnimationFrame(frame);
    };
  }, []);

  return <main className="manual-shell">
    <header className="manual-topbar">
      <Link className="manual-brand" href="/"><Image src="/h1dr4-mark.jpg" alt="H1DR4" width={32} height={32} /><strong>H1DR4 AttackGraph</strong></Link>
      <div className="manual-breadcrumb"><span>Documentation</span><i>/</i><b>Core concepts and API</b></div>
      <div className="manual-actions"><span>v0.1</span><Link href="/">Open dashboard</Link></div>
    </header>

    <div className="manual-layout">
      <aside className="manual-sidebar">
        <div className="manual-sidebar-intro"><strong>Documentation</strong><p>Operator and developer guide</p></div>
        <nav aria-label="Documentation navigation">
          {DOC_NAV.map((group) => <div className="manual-nav-group" key={group.group}><span>{group.group}</span>{group.items.map(([id, label]) => <a className={activeSection === id ? 'active' : ''} aria-current={activeSection === id ? 'location' : undefined} href={`#${id}`} onClick={() => setActiveSection(id)} key={id}>{label}</a>)}</div>)}
        </nav>
        <div className="manual-sidebar-status"><i /><span>Prototype documentation</span><small>Local-first · authorized use</small></div>
      </aside>

      <article className="manual-content">
        <section className="manual-hero" id="overview">
          <span className="manual-eyebrow">Overview</span>
          <h1>H1DR4 AttackGraph</h1>
          <p className="manual-lead">AttackGraph is an MCP service for persistent security operations. It stores engagement state in Sibyl, validates agent actions and correlates execution evidence from local tools or H3RETIK.</p>
          <div className="manual-paths" aria-label="Documentation paths">
            <a href="#quickstart"><span>Operator</span><strong>Run it locally</strong><p>Start the service, open an engagement and connect a worker.</p></a>
            <a href="#mcp"><span>Agent developer</span><strong>Integrate through MCP</strong><p>Read the agent lifecycle and available tool contract.</p></a>
            <a href="#telemetry"><span>Executor integrator</span><strong>Report trustworthy evidence</strong><p>Implement typed telemetry and proof correlation.</p></a>
          </div>

          <div className="manual-section-block">
            <SectionHeading eyebrow="System overview" title="Four components, one engagement">
              The engagement is the durable unit of work. Agents and execution sessions can be replaced without losing the accumulated operational state.
            </SectionHeading>
            <div className="manual-architecture" aria-label="AttackGraph system architecture">
              <div className="manual-architecture-main">
                <article><small>Reasoning</small><strong>MCP agent</strong><p>Reads context, plans work and reports semantic outcomes.</p></article>
                <b aria-hidden="true">→</b>
                <article className="primary"><small>Control plane</small><strong>AttackGraph</strong><p>Resolves identity, checks scope and normalizes telemetry.</p></article>
                <b aria-hidden="true">→</b>
                <article><small>Durable memory</small><strong>Sibyl</strong><p>Stores the graph, history, evidence and regressions.</p></article>
              </div>
              <div className="manual-architecture-execution"><span>Execution and proof</span><i aria-hidden="true">↕</i><article><strong>Local tools or H3RETIK</strong><p>Runs bounded work and returns sanitized executor evidence.</p></article></div>
            </div>
            <dl className="manual-concepts">
              <div><dt>Engagement</dt><dd>An authorized target, scope, policy and shared operational history.</dd></div>
              <div><dt>Worker</dt><dd>A human or agent identity acting inside an engagement.</dd></div>
              <div><dt>Session</dt><dd>Temporary execution capacity. It is not the target or source of truth.</dd></div>
              <div><dt>Evidence</dt><dd>A redacted assertion or executor proof linked to an action and target.</dd></div>
            </dl>
            <aside className="manual-callout note"><strong>Important distinction</strong><p>Sibyl owns durable operational knowledge. H3RETIK provides disposable compute. The dashboard only projects the state stored in AttackGraph.</p></aside>
          </div>
        </section>

        <section className="manual-section" id="request-path">
          <SectionHeading eyebrow="Request lifecycle" title="How one action moves through the system">
            Planning, execution and evidence are separate records. A model never turns its own statement into verified proof.
          </SectionHeading>
          <ol className="manual-lifecycle">
            <li><b>1</b><div><strong>Connect</strong><p>The worker authenticates with a revocable identity scoped to one or more engagements.</p></div></li>
            <li><b>2</b><div><strong>Recall context</strong><p>The worker reads the reporting contract and the latest Sibyl brief before planning.</p></div></li>
            <li><b>3</b><div><strong>Request an action</strong><p>AttackGraph records the target, command, purpose, risk, timeout and execution lane.</p></div></li>
            <li><b>4</b><div><strong>Execute</strong><p>The approved work runs locally or inside an existing H3RETIK session.</p></div></li>
            <li><b>5</b><div><strong>Report meaning</strong><p>The agent records what the result means using typed telemetry and a stable idempotency key.</p></div></li>
            <li><b>6</b><div><strong>Correlate proof</strong><p>Authenticated executor evidence can promote the matching assertion to attested or verified.</p></div></li>
            <li><b>7</b><div><strong>Render state</strong><p>The dashboard derives posture, findings, loot and relationships from qualifying Sibyl records.</p></div></li>
          </ol>
          <aside className="manual-callout warning"><strong>Verification rule</strong><p>A requested action or successful-looking message is not proof. High-impact posture requires correlated executor evidence.</p></aside>
        </section>

        <section className="manual-section" id="quickstart">
          <SectionHeading eyebrow="Local quick start" title="Start the MCP service and dashboard">
            Python 3.11+ and <code>uv</code> are required. The dashboard additionally uses Node.js 22.13+.
          </SectionHeading>
          <div className="manual-two-column">
            <div>
              <CodeBlock label="Install and start the MCP server">{`git clone https://github.com/nativ3ai/h1dr4-attackgraph
cd h1dr4-attackgraph
uv sync --extra dev
cp .env.example .env
uv run h1dr4-attackgraph`}</CodeBlock>
              <CodeBlock label="Start the operator dashboard">{`./scripts/run-dashboard.sh
# open http://localhost:3000`}</CodeBlock>
            </div>
            <ol className="manual-setup-list">
              <li><b>1</b><div><strong>Open the console</strong><p>Register a passkey, or continue unclaimed while developing locally.</p></div></li>
              <li><b>2</b><div><strong>Create an engagement</strong><p>Define the exact target, allowlist, mode, lanes and rules.</p></div></li>
              <li><b>3</b><div><strong>Create a worker identity</strong><p>Open Team + Agents and copy the generated configuration. The token is shown once.</p></div></li>
              <li><b>4</b><div><strong>Restart the MCP host</strong><p>The worker can now read the reporting contract and engagement brief.</p></div></li>
            </ol>
          </div>
          <CodeBlock label="MCP client configuration">{`{
  "mcpServers": {
    "h1dr4-attackgraph": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/h1dr4-attackgraph", "run", "h1dr4-attackgraph"],
      "env": {
        "ATTACKGRAPH_DB_PATH": "/absolute/path/attackgraph/sibyl.db",
        "ATTACKGRAPH_CONTROL_DB_PATH": "/absolute/path/attackgraph/control.db",
        "ATTACKGRAPH_OPERATOR_ID": "your-operator-id",
        "ATTACKGRAPH_AGENT_TOKEN": "atk_agent_shown_once"
      }
    }
  }
}`}</CodeBlock>
          <div className="manual-table-wrap"><table><caption>Runtime configuration</caption><thead><tr><th>Variable</th><th>Default or source</th><th>Purpose</th></tr></thead><tbody>{ENVIRONMENT.map(([name, value, purpose]) => <tr key={name}><td><code>{name}</code></td><td>{value}</td><td>{purpose}</td></tr>)}</tbody></table></div>
        </section>

        <section className="manual-section" id="mcp">
          <SectionHeading eyebrow="MCP API" title="The agent interface">
            At the start of a fresh session, call <code>attackgraph_get_reporting_contract</code>, then load <code>attackgraph_get_brief</code>. Refresh the brief whenever context may be stale.
          </SectionHeading>
          <div className="manual-procedure"><span>Recommended sequence</span><code>select engagement → reporting contract → brief → request action → report event → checkpoint</code></div>
          <div className="manual-api-table" role="table" aria-label="AttackGraph MCP tools">
            <div className="head" role="row"><b>Type</b><b>Tool</b><b>Purpose</b></div>
            {MCP_TOOLS.map(([kind, name, purpose]) => <div role="row" key={name}><span className={`manual-kind kind-${kind.toLowerCase()}`}>{kind}</span><code>{name}</code><p>{purpose}</p></div>)}
          </div>
          <aside className="manual-callout note"><strong>Legacy compatibility</strong><p><code>attackgraph_record_observation</code> remains available for older clients. New integrations should use typed telemetry; legacy posture claims are always unverified.</p></aside>
        </section>

        <section className="manual-section" id="telemetry">
          <SectionHeading eyebrow="Telemetry contract" title="Report meaning separately from proof">
            Telemetry is the shared language between an MCP worker, AttackGraph, an executor, Sibyl and the dashboard. Agent reports describe meaning; executor events establish what actually ran.
          </SectionHeading>
          <aside className="manual-callout note"><strong>Write for the operator</strong><p>Use a concrete semantic summary such as “Administrator session accepted without valid credentials.” Do not use transport labels such as “result imported” as the finding title.</p></aside>
          <div className="manual-assurance">
            <article><span>Asserted</span><strong>Agent report</strong><p>Useful operational state, but insufficient for a high-impact posture.</p></article>
            <article><span>Attested</span><strong>Executor evidence</strong><p>Authenticated proof exists, but target or action correlation is incomplete.</p></article>
            <article><span>Verified</span><strong>Fully correlated</strong><p>Target, action, session, outcome and proof reference agree.</p></article>
          </div>
          <div className="manual-table-wrap"><table><caption>Core event types</caption><thead><tr><th>Event</th><th>When to emit it</th></tr></thead><tbody>{EVENTS.map(([name, meaning]) => <tr key={name}><td><code>{name}</code></td><td>{meaning}</td></tr>)}</tbody></table></div>
          <CodeBlock label="Agent assertion">{`{
  "engagement_id": "eng-example",
  "event_type": "finding.confirmed",
  "summary": "Owned fixture accepted an unauthorized administrator session",
  "target": "demo.internal",
  "outcome": "success",
  "technique": "authentication_bypass",
  "confidence": 0.98,
  "action_id": "act-example",
  "entities": [{"id": "login", "type": "endpoint", "label": "/login", "layer": "identity"}],
  "relationships": [{"from": "event", "to": "login", "type": "observed_on"}],
  "attributes": {"posture_signal": "target_compromised", "http_status": 200},
  "idempotency_key": "finding:admin-auth-bypass"
}`}</CodeBlock>
          <div className="manual-rule-list">
            <article><strong>Exact scope</strong><p><code>target</code> must exactly match the engagement allowlist.</p></article>
            <article><strong>Stable identity</strong><p>Reuse entity IDs across events and one opaque <code>idempotency_key</code> when proof promotes an assertion.</p></article>
            <article><strong>Known graph</strong><p>Relationships may reference <code>event</code>, <code>target</code>, entities declared now, or entities and records already retained by Sibyl.</p></article>
            <article><strong>Typed loot</strong><p>Use <code>artifact</code> only with <code>loot.discovered</code>. Keep payload evidence sealed and report its type, sensitivity and graph references.</p></article>
            <article><strong>No self-verification</strong><p>Agent input cannot mark itself verified or supply trusted attestation.</p></article>
          </div>
        </section>

        <section className="manual-section" id="h3retik">
          <SectionHeading eyebrow="H3RETIK execution" title="Optional disposable compute">
            AttackGraph works without H3RETIK. When remote execution is needed, it runs commands only inside an existing paid session and returns sanitized evidence to the engagement.
          </SectionHeading>
          <div className="manual-table-wrap"><table><caption>Execution modes</caption><thead><tr><th>Mode</th><th>Execution</th><th>Use</th></tr></thead><tbody>
            <tr><td><code>manual_only</code></td><td>No dispatch</td><td>Human-assisted arenas and workflows where AttackGraph records plans only.</td></tr>
            <tr><td><code>local_lab</code></td><td>Local tooling</td><td>Owned targets where the operator or connected worker runs commands locally.</td></tr>
            <tr><td><code>autonomous_lab</code></td><td>Gated H3RETIK job</td><td>Owned sandbox targets with configured executor credentials and approval.</td></tr>
          </tbody></table></div>
          <div className="manual-two-column">
            <CodeBlock label="Operator-only environment">{`export H3RETIK_WALLET='0x...'
export H3RETIK_TOKEN='...'
export H3RETIK_SESSION_ID='...'
export ATTACKGRAPH_EXECUTION_APPROVAL_CODE='one-time-human-secret'
export ATTACKGRAPH_H3RETIK_ATTESTATION_TOKEN='separate-adapter-only-secret'
uv run h1dr4-attackgraph`}</CodeBlock>
            <ol className="manual-setup-list compact">
              <li><b>1</b><div><strong>Rent a session</strong><p>The operator accepts the current terms and provisions the smallest suitable session.</p></div></li>
              <li><b>2</b><div><strong>Bind it</strong><p>Attach the returned session ID to the AttackGraph engagement.</p></div></li>
              <li><b>3</b><div><strong>Request and approve work</strong><p>The worker proposes an action; the server validates scope before dispatch.</p></div></li>
              <li><b>4</b><div><strong>Ingest evidence</strong><p>Sanitized results return through the adapter and correlate in Sibyl.</p></div></li>
              <li><b>5</b><div><strong>Dispose</strong><p>The runtime expires or is destroyed while engagement memory remains.</p></div></li>
            </ol>
          </div>
          <aside className="manual-callout note"><strong>Base boundary</strong><p>Base settles remote H3RETIK compute. Targets, prompts, credentials, findings and graph state stay off-chain.</p></aside>
        </section>

        <section className="manual-section" id="security">
          <SectionHeading eyebrow="Security model" title="Separate identity, memory, execution and proof">
            No browser session, worker token or executor credential should silently become universal authority.
          </SectionHeading>
          <dl className="manual-boundaries">
            <div><dt>Human access</dt><dd><strong>Passkeys</strong><p>The browser stores an authenticated session. AttackGraph stores public credentials and hashed sessions.</p></dd></div>
            <div><dt>Worker access</dt><dd><strong>Revocable tokens</strong><p>Each token carries one actor identity and can access only engagements with membership.</p></dd></div>
            <div><dt>Executor access</dt><dd><strong>Adapter-only attestation</strong><p>The H3RETIK attestation token never appears in worker MCP configuration or Sibyl memory.</p></dd></div>
            <div><dt>Durable storage</dt><dd><strong>Redact before persistence</strong><p>Credentials, authorization values, cookies, private keys and tokens are removed before storage.</p></dd></div>
          </dl>
          <div className="manual-table-wrap"><table><caption>Data ownership</caption><thead><tr><th>Layer</th><th>Owns</th><th>Must not own</th></tr></thead><tbody>
            <tr><td>Control database</td><td>Passkeys, users, memberships, worker identities, session bindings</td><td>Findings or executor secrets</td></tr>
            <tr><td>Sibyl database</td><td>Redacted graph, events, attempts, findings, loot references, proof metadata</td><td>Raw credentials or adapter tokens</td></tr>
            <tr><td>Runtime</td><td>Transient processes, command output and job artifacts</td><td>Long-term engagement truth</td></tr>
            <tr><td>Base</td><td>Remote-compute settlement state</td><td>Targets, prompts, findings, loot or graph state</td></tr>
            <tr><td>Browser</td><td>Authenticated session and local view preferences</td><td>Executor wallet or H3RETIK bearer credential</td></tr>
          </tbody></table></div>
          <aside className="manual-callout danger"><strong>Authorized use only</strong><p>Allowlists and execution lanes enforce technical scope; they do not replace permission from the system owner.</p></aside>
        </section>

        <section className="manual-section" id="development">
          <SectionHeading eyebrow="Development" title="Repository guide and validation">
            The Python package owns MCP, policy, memory, telemetry and the dashboard API. The Vinext application owns operator presentation.
          </SectionHeading>
          <div className="manual-repo-list">
            <article><code>src/h1dr4_attackgraph/server.py</code><p>FastMCP tool surface and worker principal resolution.</p></article>
            <article><code>service.py</code><p>Engagement orchestration, action lifecycle and proof correlation.</p></article>
            <article><code>telemetry.py</code><p>Telemetry v1 schema, normalization, assurance and H3RETIK attestation.</p></article>
            <article><code>memory.py</code><p>Sibyl hot graph, append-only history and reconstruction.</p></article>
            <article><code>identity.py</code><p>Passkeys, memberships, worker tokens and H3RETIK bindings.</p></article>
            <article><code>policy.py · posture.py · redaction.py</code><p>Scope gates, deterministic dashboard state and secret handling.</p></article>
            <article><code>dashboard/app</code><p>Operator console, attack map, architecture view and documentation.</p></article>
            <article><code>tests</code><p>Memory, policy, identity, telemetry, MCP and dashboard contracts.</p></article>
          </div>
          <CodeBlock label="Validate before handoff">{`uv sync --extra dev
uv run ruff check .
uv run pytest
npm --prefix dashboard install
npm --prefix dashboard run lint
npm --prefix dashboard run build`}</CodeBlock>
          <div className="manual-test-list">
            <article><strong>Memory deletion test</strong><p>A new Sibyl database must not reconstruct the previous engagement brief.</p><code>uv run pytest tests/test_memory.py -k deletion</code></article>
            <article><strong>Proof promotion test</strong><p>An assertion is promoted in place only after authenticated executor correlation.</p><code>uv run pytest tests/test_telemetry.py</code></article>
          </div>
          <aside className="manual-callout warning"><strong>Current status</strong><p>This is a hackathon prototype. Use it only on systems you own or are explicitly authorized to test.</p></aside>
        </section>

        <footer className="manual-footer"><span>H1DR4 AttackGraph documentation</span><Link href="/">Return to dashboard</Link></footer>
      </article>
    </div>
  </main>;
}
