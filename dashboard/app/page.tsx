'use client';

import { useEffect, useMemo, useState } from 'react';
import { fallbackSnapshot, type Action, type Engagement, type GraphNode, type MemoryEvent, type Snapshot } from './model';

type Connection = 'connecting' | 'live' | 'preview' | 'error';

export default function Home() {
  const [snapshot, setSnapshot] = useState<Snapshot>(fallbackSnapshot);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementId, setEngagementId] = useState('');
  const [connection, setConnection] = useState<Connection>('connecting');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [view, setView] = useState<'graph' | 'timeline'>('graph');
  const [zoom, setZoom] = useState(1);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      void fetch('/api/engagements', { cache: 'no-store' })
        .then((response) => {
          if (!response.ok) throw new Error('dashboard API unavailable');
          return response.json() as Promise<{ engagements: Engagement[] }>;
        })
        .then((payload) => {
          if (cancelled) return;
          setEngagements(payload.engagements);
          if (payload.engagements.length) {
            setEngagementId((current) => current || payload.engagements.at(-1)!.engagement_id);
          } else setConnection('preview');
        })
        .catch(() => { if (!cancelled) setConnection('preview'); });
    };
    const kickoff = window.setTimeout(load, 0);
    const timer = window.setInterval(load, 10000);
    return () => { cancelled = true; window.clearTimeout(kickoff); window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    if (!engagementId) return;
    let cancelled = false;
    const refresh = () => {
      void fetch(`/api/engagements/${engagementId}`, { cache: 'no-store' })
        .then((response) => {
          if (!response.ok) throw new Error('engagement unavailable');
          return response.json() as Promise<Snapshot>;
        })
        .then((payload) => {
          if (!cancelled) { setSnapshot(payload); setConnection('live'); }
        })
        .catch(() => { if (!cancelled) setConnection('error'); });
    };
    const kickoff = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 3000);
    return () => { cancelled = true; window.clearTimeout(kickoff); window.clearInterval(timer); };
  }, [engagementId]);

  const nodeById = useMemo(() => Object.fromEntries(snapshot.nodes.map((node) => [node.id, node])), [snapshot.nodes]);
  const scope = snapshot.engagement.allowed_lanes.join(', ');
  const action = snapshot.primary_action;

  return (
    <main className="shell">
      <div className="screen-noise" aria-hidden="true" />
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">[H1]</span>
          <div><strong>H1DR4//ATTACKGRAPH</strong><span>OFFENSIVE MEMORY CONSOLE</span></div>
        </div>
        <label className="engagement-switcher">
          <span>ACTIVE ENGAGEMENT</span>
          <select value={engagementId} onChange={(event) => { setEngagementId(event.target.value); setSelectedNode(null); }}>
            {!engagements.length && <option value="">{snapshot.engagement.title}</option>}
            {engagements.map((engagement) => <option value={engagement.engagement_id} key={engagement.engagement_id}>{engagement.title}</option>)}
          </select>
        </label>
        <div className={`system-state ${connection}`}><span className="pulse" /><div><strong>{connection === 'live' ? 'SIBYL::ONLINE' : connection === 'connecting' ? 'LINK::PENDING' : 'LOCAL::PREVIEW'}</strong><span>{connection === 'live' ? `memory_sync / ${formatTime(snapshot.memory.last_event)}Z` : 'awaiting local memory bus'}</span></div></div>
      </header>

      <section className="scopebar">
        <div><span>/ MODE</span><strong>{snapshot.engagement.mode.replaceAll('_', ' ').toUpperCase()}</strong></div>
        <div><span>/ PRIMARY TARGET</span><strong>{snapshot.engagement.target}</strong></div>
        <div className="scope-wide"><span>/ AUTHORIZED SCOPE</span><strong>{snapshot.engagement.scope} :: {scope}</strong></div>
        <div className="scope-status"><i /> [ SCOPE::VERIFIED ]</div>
      </section>

      <div className="workspace">
        <aside className="intel-column">
          <section className="metric-strip">
            <div><strong>{pad(snapshot.stats.nodes)}</strong><span>:: Nodes</span></div>
            <div><strong>{pad(snapshot.stats.evidence)}</strong><span>:: Evidence</span></div>
            <div><strong>{pad(snapshot.stats.pending)}</strong><span>:: Pending</span></div>
          </section>
          <IntelSection title="Confirmed" count={String(snapshot.brief.confirmed.length)} tone="confirmed">
            {snapshot.brief.confirmed.slice(-4).reverse().map((item) => <IntelItem key={item.id} title={item.statement} meta={`${item.source} · confidence ${item.confidence.toFixed(2)}`} />)}
          </IntelSection>
          <IntelSection title="Open hypotheses" count={String(snapshot.brief.open_hypotheses.length)} tone="hypothesis">
            {snapshot.brief.open_hypotheses.slice(-4).reverse().map((item) => <IntelItem key={item.id} title={item.statement} meta="open · requires evidence" />)}
          </IntelSection>
          <IntelSection title="Exhausted paths" count={String(snapshot.brief.exhausted_paths.length)} tone="exhausted">
            {snapshot.brief.exhausted_paths.slice(-3).reverse().map((item) => <IntelItem key={item.id} title={item.approach} meta={`${item.outcome} · do not repeat`} />)}
          </IntelSection>
        </aside>

        <section className="graph-panel">
          <div className="panel-heading">
            <div><span>{view === 'graph' ? '// LIVE TOPOLOGY' : '// SIBYL EVENT LOG'}</span><h1><em>&gt;_</em> {view === 'graph' ? 'TARGET ATTACK SURFACE' : 'ENGAGEMENT TIMELINE'}</h1></div>
            <div className="graph-tools" aria-label="Graph controls">
              <button type="button" className={view === 'graph' ? 'active' : ''} onClick={() => setView('graph')}>[G] GRAPH</button>
              <button type="button" className={view === 'timeline' ? 'active' : ''} onClick={() => setView('timeline')}>[T] LOG</button>
              <button type="button" aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(.72, value - .1))}>[−]</button>
              <button type="button" aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(1.35, value + .1))}>[+]</button>
            </div>
          </div>

          {view === 'graph' ? (
            <div className="graph-canvas">
              <div className="grid-lines" />
              <div className="map-index" aria-hidden="true"><span>SYS.MAP / 06</span><strong>GLASSHOUSE</strong><small>X.49 / Y.42 / Z.00</small></div>
              <div className="coordinate-rail coordinate-x" aria-hidden="true">00····10····20····30····40····50····60····70····80····90····99</div>
              <div className="coordinate-rail coordinate-y" aria-hidden="true">00<br />·<br />20<br />·<br />40<br />·<br />60<br />·<br />80<br />·<br />99</div>
              <div className="graph-stage" style={{ transform: `scale(${zoom})` }}>
                <svg className="edges" aria-hidden="true" viewBox="0 0 100 100" preserveAspectRatio="none">
                  {snapshot.edges.map((edge) => nodeById[edge.from] && nodeById[edge.to] ? <line key={`${edge.from}-${edge.to}`} x1={nodeById[edge.from].x} y1={nodeById[edge.from].y} x2={nodeById[edge.to].x} y2={nodeById[edge.to].y} /> : null)}
                </svg>
                {snapshot.nodes.map((node, index) => (
                  <button className={`graph-node ${node.kind} ${selectedNode?.id === node.id ? 'selected' : ''}`} data-kind={node.kind} key={node.id} style={{ left: `${node.x}%`, top: `${node.y}%` }} type="button" onClick={() => setSelectedNode(node)}>
                    <span className="node-core" /><span className="node-index">N::{pad(index + 1)}</span><strong>{node.label}</strong><small>{node.meta}</small>
                  </button>
                ))}
              </div>
              <div className="graph-legend"><span><i className="legend-confirmed" /> [C] Confirmed</span><span><i className="legend-hypothesis" /> [?] Hypothesis</span><span><i className="legend-regression" /> [R] Regression</span></div>
              {selectedNode && <NodeInspector node={selectedNode} onClose={() => setSelectedNode(null)} />}
            </div>
          ) : <CentralTimeline events={snapshot.events} />}

          <div className="memory-directive"><span>SIBYL::DIRECTIVE</span><p><b>root@attackgraph:~$</b> {snapshot.brief.agent_instruction}<i aria-hidden="true" /></p></div>
        </section>

        <aside className="operations-column">
          <ActionCard action={action} onReview={() => { const node = snapshot.nodes.find((item) => item.id === action?.id); if (node) { setView('graph'); setSelectedNode(node); } }} />
          <section className="evidence-feed">
            <div className="section-label"><span>EVIDENCE STREAM</span><b>{connection === 'live' ? 'LIVE' : 'PREVIEW'}</b></div>
            {snapshot.events.slice(0, 5).map((event) => <TimelineItem event={event} key={event.id} />)}
          </section>
          <section className="regression-card">
            <div className="section-label"><span>REGRESSION WATCH</span><b>{snapshot.brief.regressions.length}</b></div>
            {snapshot.brief.regressions.length ? snapshot.brief.regressions.slice(-2).reverse().map((item) => <div className="regression-row" key={item.id}><span className="check">✓</span><div><strong>{item.name}</strong><small>{item.expected}</small></div></div>) : <EmptyState text="No regression checks yet" />}
          </section>
        </aside>
      </div>

      <footer className="statusbar">
        <span>ENGAGEMENT//<strong>{snapshot.engagement.engagement_id}</strong></span>
        <span>OPERATOR//<strong>{snapshot.engagement.operator_id?.toUpperCase() || 'ISOLATED'}</strong></span>
        <span className="status-spacer" />
        {engagementId && <a href={`/api/engagements/${engagementId}/export`}>[ EXPORT::JSON ]</a>}
        <span>LAST_EVENT//<strong>{formatTime(snapshot.memory.last_event)}Z</strong></span>
        <span>EVENTS//<strong>{pad(snapshot.memory.event_count)}</strong></span>
      </footer>
    </main>
  );
}

function IntelSection({ title, count, tone, children }: { title: string; count: string; tone: string; children: React.ReactNode }) {
  return <section className={`intel-section ${tone}`}><div className="section-label"><span>{title}</span><b>{count}</b></div><div className="intel-list">{children || <EmptyState text="No entries" />}</div></section>;
}
function IntelItem({ title, meta }: { title: string; meta: string }) { return <div className="intel-item"><i /><div><strong>{title}</strong><small>{meta.replaceAll(' · ', ' :: ')}</small></div></div>; }
function EmptyState({ text }: { text: string }) { return <p className="empty-state">{text}</p>; }

function ActionCard({ action, onReview }: { action: Action | null; onReview: () => void }) {
  return <section className="action-card"><div className="section-label"><span>ACTION::QUEUE</span><b>[{action ? '01' : '00'}]</b></div>{action ? <><div className="action-id"><span>{action.id.toUpperCase()}</span><em>{action.status.replaceAll('_', '::').toUpperCase()}</em></div><h2>{action.purpose}</h2><code><b>$</b> {action.command}<i aria-hidden="true" /></code><dl><div><dt>LANE//</dt><dd>{action.lane.toUpperCase()}</dd></div><div><dt>RUNTIME//</dt><dd>≤ {action.max_minutes} MIN</dd></div><div><dt>BUDGET//</dt><dd>{action.budget_usdc.toFixed(2)} USDC</dd></div></dl><button type="button" className="review-action" onClick={onReview}>[ ENTER ] REVIEW ACTION</button></> : <EmptyState text="No actions awaiting review" />}</section>;
}

function TimelineItem({ event }: { event: MemoryEvent }) {
  return <div className={`timeline-item ${eventTone(event.type)}`}><time>{formatTime(event.time)}</time><i /><div><strong>{event.title}</strong><small>{event.detail}</small></div></div>;
}

function CentralTimeline({ events }: { events: MemoryEvent[] }) {
  return <div className="central-timeline">{events.length ? events.map((event, index) => <div className="central-event" key={event.id}><span>{String(index + 1).padStart(2, '0')}</span><time>{formatDate(event.time)} · {formatTime(event.time)}</time><i className={eventTone(event.type)} /><div><strong>{event.title}</strong><p>{event.detail}</p></div></div>) : <EmptyState text="No Sibyl events recorded" />}</div>;
}

function NodeInspector({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  return <aside className="node-inspector"><button type="button" onClick={onClose} aria-label="Close node details">[X]</button><span>┌─ NODE::INSPECT / {node.meta}</span><h2>&gt; {node.label}</h2><pre>{JSON.stringify(node.detail, null, 2)}</pre><small>└─ EOF</small></aside>;
}

function eventTone(type: string) { if (type.includes('hypothesis')) return 'hypothesis'; if (type.includes('attempt')) return 'exhausted'; if (type.includes('engagement') || type.includes('recall')) return 'memory'; return 'confirmed'; }
function pad(value: number) { return String(value).padStart(2, '0'); }
function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? '—' : date.toLocaleTimeString('en-GB', { timeZone: 'UTC', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? 'UNKNOWN' : date.toLocaleDateString('en-US', { timeZone: 'UTC', month: 'short', day: '2-digit' }).toUpperCase(); }
