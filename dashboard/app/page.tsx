'use client';

import Image from 'next/image';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ArchitectureView from './architecture';
import { fallbackSnapshot, type Action, type Attempt, type AuthStatus, type Engagement, type GraphEdge, type GraphNode, type H3retikSession, type IdentitySnapshot, type LootArtifact, type MemoryEvent, type Snapshot } from './model';

type Connection = 'connecting' | 'live' | 'preview' | 'error';
type ConsoleView = 'overview' | 'map' | 'operations' | 'intel' | 'activity' | 'architecture';
type TacticalFloor = { id: string; label: string; subtitle: string };
type TacticalRoom = { node: GraphNode | null; id: string; floor: number; x: number; y: number; width: number; height: number; door: 'north' | 'east' | 'south' | 'west' };
type TacticalCorridor = { id: string; x: number; y: number; width: number; height: number };
type TacticalPlan = { archetype: 'SPINE-H' | 'SPINE-V' | 'CROSS'; corridors: TacticalCorridor[]; hub: { x: number; y: number }; core: { x: number; y: number; width: number; height: number } };
type TacticalModel = { profile: string; floors: TacticalFloor[]; rooms: TacticalRoom[]; plans: TacticalPlan[]; nodeFloors: Record<string, number>; seed: number };

export default function Home() {
  const [snapshot, setSnapshot] = useState<Snapshot>(fallbackSnapshot);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementId, setEngagementId] = useState('');
  const [connection, setConnection] = useState<Connection>('connecting');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [view, setView] = useState<ConsoleView>('overview');
  const [zoom, setZoom] = useState(1);
  const [query, setQuery] = useState('');
  const [showOperations, setShowOperations] = useState(false);
  const [showRawNode, setShowRawNode] = useState(false);
  const [lastViewedAt, setLastViewedAt] = useState('');
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [localBypass, setLocalBypass] = useState(false);
  const [identityOpen, setIdentityOpen] = useState(false);
  const [postureOpen, setPostureOpen] = useState(false);
  const [identity, setIdentity] = useState<IdentitySnapshot>({ members: [], agents: [], h3retik_sessions: [] });
  const [actorFilter, setActorFilter] = useState('');
  const [sessionFilter, setSessionFilter] = useState('');
  const [activeFloor, setActiveFloor] = useState(0);
  const [inviteToken, setInviteToken] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);
  const initializedViews = useRef(new Set<string>());

  const refreshAuth = useCallback(() => fetch('/api/auth/status', { cache: 'no-store' })
    .then((response) => response.json() as Promise<AuthStatus>)
    .then((status) => { setAuth(status); return status; }), []);

  useEffect(() => {
    void refreshAuth().catch(() => setAuth({ mode: 'optional', state: 'open', authenticated: false, user: null, passkey_count: 0, passkey_supported: true }));
    const readInvite = window.setTimeout(() => setInviteToken(new URLSearchParams(window.location.search).get('invite') || ''), 0);
    return () => window.clearTimeout(readInvite);
  }, [refreshAuth]);

  useEffect(() => {
    if (!auth?.state || auth.state === 'locked') return;
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
  }, [auth?.state]);

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
          if (!cancelled) {
            const viewKey = `attackgraph:last-view:${engagementId}`;
            if (!initializedViews.current.has(engagementId)) {
              setLastViewedAt(window.localStorage.getItem(viewKey) || '');
              initializedViews.current.add(engagementId);
            }
            window.localStorage.setItem(viewKey, payload.memory.last_event);
            setSnapshot(payload);
            setConnection('live');
          }
        })
        .catch(() => { if (!cancelled) setConnection('error'); });
    };
    const kickoff = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 3000);
    return () => { cancelled = true; window.clearTimeout(kickoff); window.clearInterval(timer); };
  }, [engagementId]);

  const refreshIdentity = useCallback(() => {
    if (!engagementId) return Promise.resolve();
    return fetch(`/api/engagements/${engagementId}/identity`, { cache: 'no-store' })
      .then((response) => {
        if (!response.ok) throw new Error('identity unavailable');
        return response.json() as Promise<IdentitySnapshot>;
      })
      .then(setIdentity);
  }, [engagementId]);

  useEffect(() => {
    if (!engagementId || auth?.state === 'locked') return;
    void refreshIdentity().catch(() => setIdentity({ members: [], agents: [], h3retik_sessions: [] }));
  }, [auth?.state, engagementId, refreshIdentity]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      const isField = event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement || event.target instanceof HTMLTextAreaElement;
      if (event.key === 'Escape') {
        setSelectedNode(null);
        setShowOperations(false);
        setShowRawNode(false);
        setPostureOpen(false);
        setQuery('');
        searchRef.current?.blur();
        return;
      }
      if (isField) return;
      if (event.key === '/') { event.preventDefault(); setView('map'); window.setTimeout(() => searchRef.current?.focus(), 0); }
      if (event.key === '1' || event.key.toLowerCase() === 'o') setView('overview');
      if (event.key === '2' || event.key.toLowerCase() === 'm') setView('map');
      if (event.key === '3') setView('operations');
      if (event.key === '4' || event.key.toLowerCase() === 'i') setView('intel');
      if (event.key === '5' || event.key.toLowerCase() === 'l') setView('activity');
      if (event.key === '6' || event.key.toLowerCase() === 'd') setView('architecture');
      if (event.key.toLowerCase() === 'a') {
        setShowOperations(false);
        setView('operations');
      }
      if (event.key === '+' || event.key === '=') setZoom((value) => Math.min(1.35, value + .1));
      if (event.key === '-') setZoom((value) => Math.max(.72, value - .1));
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const normalizedQuery = query.trim().toLowerCase();
  const visibleNodes = useMemo(() => snapshot.nodes.filter((node) => {
    const queryMatches = !normalizedQuery || `${node.label} ${node.meta} ${node.kind} ${node.actor_name || ''}`.toLowerCase().includes(normalizedQuery);
    const actorMatches = !actorFilter || node.kind === 'target' || node.actor_id === actorFilter;
    const sessionMatches = !sessionFilter || node.kind === 'target' || node.h3retik_session_id === sessionFilter;
    return queryMatches && actorMatches && sessionMatches;
  }), [actorFilter, normalizedQuery, sessionFilter, snapshot.nodes]);
  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEvents = useMemo(() => snapshot.events.filter((event) => {
    const queryMatches = !normalizedQuery || `${event.title} ${event.detail} ${event.type} ${event.actor_name || ''}`.toLowerCase().includes(normalizedQuery);
    const actorMatches = !actorFilter || event.actor_id === actorFilter;
    const sessionMatches = !sessionFilter || event.h3retik_session_id === sessionFilter;
    return queryMatches && actorMatches && sessionMatches;
  }), [actorFilter, normalizedQuery, sessionFilter, snapshot.events]);
  const tacticalModel = useMemo(() => buildTacticalModel(snapshot), [snapshot]);
  const visibleSelectedNode = selectedNode && visibleNodeIds.has(selectedNode.id) ? selectedNode : null;
  const focusedNode = visibleSelectedNode || visibleNodes.find((node) => node.kind === 'target') || visibleNodes.at(0) || null;
  const scope = snapshot.engagement.allowed_lanes.join(', ');
  const action = snapshot.primary_action;
  const posture = snapshot.posture || fallbackSnapshot.posture;
  const latestEvent = snapshot.events.at(0);
  const newEventCount = lastViewedAt ? snapshot.events.filter((event) => new Date(event.time) > new Date(lastViewedAt)).length : snapshot.events.length;
  const topHypothesis = snapshot.brief.open_hypotheses.at(-1);
  const reviewAction = () => {
    setView('map');
    setQuery('');
    const node = snapshot.nodes.find((item) => item.id === action?.id);
    if (node) { setSelectedNode(node); setActiveFloor(tacticalModel.nodeFloors[node.id] ?? 0); setShowRawNode(false); }
    setShowOperations(false);
  };
  const focusEvent = (event: MemoryEvent) => {
    const node = snapshot.nodes.find((item) => item.id === event.object_id);
    if (node) {
      setSelectedNode(node);
      setActiveFloor(tacticalModel.nodeFloors[node.id] ?? 0);
      setShowRawNode(false);
    }
  };
  const showAuthGate = !auth || auth.state === 'locked' || (auth.state === 'setup' && !localBypass) || Boolean(inviteToken && !auth.authenticated);

  return (
    <main className="shell">
      <div className="screen-noise" aria-hidden="true" />
      {showAuthGate && <PasskeyGate auth={auth} inviteToken={inviteToken} onBypass={() => setLocalBypass(true)} onAuthenticated={() => { setLocalBypass(false); void refreshAuth(); }} />}
      <header className="topbar future-topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true"><Image src="/h1dr4-mark.jpg" alt="" width={512} height={512} priority /></span>
          <div><strong>ATTACKGRAPH</strong><span>SHARED OFFENSIVE MEMORY</span></div>
        </div>
        <label className="engagement-switcher">
          <span>ACTIVE ENGAGEMENT</span>
          <select value={engagementId} onChange={(event) => { setConnection('connecting'); setLastViewedAt(''); setEngagementId(event.target.value); setSelectedNode(null); setShowRawNode(false); setActiveFloor(0); setSessionFilter(''); }}>
            {!engagements.length && <option value="">{snapshot.engagement.title}</option>}
            {engagements.map((engagement) => <option value={engagement.engagement_id} key={engagement.engagement_id}>{engagement.title}</option>)}
          </select>
        </label>
        <button className="identity-trigger" type="button" onClick={() => { setIdentityOpen(true); void refreshIdentity(); }}><span>TEAM + AGENTS</span><strong>{identity.members.length} / {identity.agents.filter((agent) => agent.status === 'active').length}</strong></button>
        <div className={`system-state ${connection}`}><span className="pulse" /><div><strong>{connection === 'live' ? 'MEMORY LIVE' : connection === 'connecting' ? 'LINKING' : connection === 'error' ? 'LINK ERROR' : 'LOCAL PREVIEW'}</strong><span>{connection === 'live' ? `${formatTime(snapshot.memory.last_event)} UTC` : connection === 'error' ? 'snapshot retained' : 'waiting for Sibyl'}</span></div></div>
      </header>

      <section className={`operation-hero posture-${posture.tone}`} aria-label="Current operation posture">
        <div className="operation-copy" data-case={snapshot.engagement.engagement_id.slice(-2).toUpperCase()}>
          <div className="operation-eyebrow"><span>CASE {snapshot.engagement.engagement_id.slice(-4).toUpperCase()}</span><i />AUTHORIZED OPERATION</div>
          <h1>{posture.display_label}</h1>
          <div className="posture-proofline">
            {posture.display_label !== posture.label && <strong>{posture.label}</strong>}
            <span>{posture.verified ? `AUTO-DERIVED FROM ${posture.evidence_count} VERIFIED SIBYL RECORD${posture.evidence_count === 1 ? '' : 'S'} · ${formatTime(posture.updated_at)} UTC` : 'NO QUALIFYING COMPROMISE EVIDENCE YET'}</span>
            <button type="button" aria-expanded={postureOpen} onClick={() => setPostureOpen((current) => !current)}>WHY THIS STATE <b>[{pad(posture.evidence_count)}]</b></button>
          </div>
          <p>{snapshot.engagement.target} <b>/</b> {snapshot.engagement.scope}</p>
          <div className="scope-capsules"><span>MODE {snapshot.engagement.mode.replaceAll('_', ' ').toUpperCase()}</span><span>LANES {scope.toUpperCase()}</span><span className="verified">SCOPE VERIFIED</span></div>
        </div>
        <div className="operation-pulse">
          <div><span>NEW INTEL</span><strong>{pad(newEventCount)}</strong><small>{latestEvent?.title || 'NO EVENTS'}</small></div>
          <div><span>OPEN PATHS</span><strong>{pad(snapshot.brief.open_hypotheses.length)}</strong><small>{topHypothesis ? 'NEEDS EVIDENCE' : 'CLEAR'}</small></div>
          <div className={identity.agents.some((agent) => agent.status === 'active') ? 'workers-active' : ''}><span>ACTIVE WORKERS</span><strong>{pad(identity.agents.filter((agent) => agent.status === 'active').length)}</strong><small>{identity.h3retik_sessions.length} H3 SESSION{identity.h3retik_sessions.length === 1 ? '' : 'S'}</small></div>
          {action && <button type="button" onClick={() => setView('operations')}>OPEN JOB RECORD <b>→</b></button>}
        </div>
      </section>

      {postureOpen && <>
        <button type="button" className="posture-proof-backdrop" aria-label="Close posture evidence" onClick={() => setPostureOpen(false)} />
        <aside className={`posture-explainer tone-${posture.tone}`} role="dialog" aria-modal="true" aria-label="Sibyl posture evidence">
          <header><div><span>SIBYL::POSTURE ENGINE</span><strong>WHY THIS STATE</strong></div><button type="button" onClick={() => setPostureOpen(false)}>[X]</button></header>
          <section className="posture-current"><span>CURRENT VERIFIED STATE</span><h2>{posture.display_label}</h2>{posture.display_label !== posture.label && <strong>{posture.label}</strong>}<p>{posture.description}</p></section>
          <section className="posture-reasons"><div><span>EVIDENCE CHAIN</span><b>{pad(posture.evidence_count)} RECORDS</b></div>{posture.reasons.length ? posture.reasons.map((reason, index) => <article key={`${reason.record_id}-${reason.signal}`}><em>{pad(index + 1)}</em><i /><div><strong>{reason.label}</strong><p>{reason.summary}</p><small>{reason.record_id} · {reason.actor_name || 'SIBYL'} · {formatTime(reason.recorded_at)} UTC</small></div></article>) : <EmptyState text="The engagement is active, but no high-confidence evidence qualifies for a stronger posture." />}</section>
          <footer><span>{posture.method.toUpperCase()}</span><small>Free-form titles, hypotheses, and staged jobs cannot change this state.</small></footer>
        </aside>
      </>}

      <nav className="experience-nav" aria-label="Operator workspace">
        <div className="experience-tabs">
          <button type="button" aria-pressed={view === 'overview'} onClick={() => setView('overview')}><b>01</b><span>OVERVIEW<small>OPERATION BRIEF</small></span></button>
          <button type="button" aria-pressed={view === 'map'} onClick={() => setView('map')}><b>02</b><span>ATTACK MAP<small>{snapshot.nodes.length} GRAPH NODES</small></span></button>
          <button type="button" aria-pressed={view === 'operations'} onClick={() => setView('operations')}><b>03</b><span>OPERATIONS<small>WORKERS + ATTACKS</small></span></button>
          <button type="button" aria-pressed={view === 'intel'} onClick={() => setView('intel')}><b>04</b><span>INTEL + LOOT<small>{snapshot.stats.loot} ARTIFACTS</small></span></button>
          <button type="button" aria-pressed={view === 'activity'} onClick={() => setView('activity')}><b>05</b><span>ACTIVITY<small>{snapshot.memory.event_count} MEMORY EVENTS</small></span></button>
          <button type="button" aria-pressed={view === 'architecture'} onClick={() => setView('architecture')}><b>06</b><span>ARCHITECTURE<small>INTERACTIVE DOCS</small></span></button>
        </div>
        <div className="experience-tools">
          {view !== 'overview' && view !== 'architecture' && <label className="panel-search"><span>/</span><input ref={searchRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="FILTER INTEL" aria-label="Filter current view" />{query && <button type="button" onClick={() => setQuery('')} aria-label="Clear filter">×</button>}</label>}
          {view !== 'architecture' && <label className="actor-filter"><span>WORKER</span><select value={actorFilter} onChange={(event) => setActorFilter(event.target.value)}><option value="">ALL</option>{identity.agents.map((agent) => <option value={agent.agent_id} key={agent.agent_id}>{agent.name} · {agent.status.toUpperCase()}</option>)}</select></label>}
          {view !== 'architecture' && <label className="session-filter"><span>SESSION</span><select value={sessionFilter} onChange={(event) => setSessionFilter(event.target.value)}><option value="">ALL</option>{identity.h3retik_sessions.map((session) => <option value={session.session_id} key={session.session_id}>{session.label}</option>)}</select></label>}
          {view === 'map' && <div className="graph-tools" aria-label="Graph controls"><button type="button" aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(.72, value - .1))}>−</button><button type="button" aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(1.35, value + .1))}>+</button></div>}
          <a className="docs-trigger" href="/docs">DOCS <b>↗</b></a>
          <button type="button" className="queue-trigger" onClick={() => setView('operations')}>JOBS <b>{action ? '01' : '00'}</b></button>
        </div>
      </nav>

      <div className={`workspace future-workspace ${view === 'operations' || view === 'intel' || view === 'architecture' ? 'wide' : ''}`}>
        <section className={`primary-surface ${view}`}>
          {view === 'overview' && <OperatorOverview snapshot={snapshot} identity={identity} model={tacticalModel} newEventCount={newEventCount} latestEvent={latestEvent} onFloor={(floor) => { setActiveFloor(floor); setView('map'); }} onEvent={(event) => { if (event.object_id) { focusEvent(event); setView('map'); } else setView('activity'); }} onOperations={() => setView('operations')} onIntel={() => setView('intel')} onActivity={() => setView('activity')} onIdentity={() => { setIdentityOpen(true); void refreshIdentity(); }} />}
          {view === 'map' && <>
            <TacticalMap model={tacticalModel} snapshot={snapshot} identity={identity} activeFloor={activeFloor} zoom={zoom} selectedNode={visibleSelectedNode} visibleNodeIds={visibleNodeIds} sessionFilter={sessionFilter} onFloor={setActiveFloor} onSession={setSessionFilter} onSelect={(node) => { setSelectedNode(node); setShowRawNode(false); }} onEvent={focusEvent} />
            {showRawNode && focusedNode && <NodeInspector node={focusedNode} onClose={() => setShowRawNode(false)} />}
            <SelectedNodeDetail node={focusedNode} edges={snapshot.edges} nodes={snapshot.nodes} onSelect={(node) => { setSelectedNode(node); setActiveFloor(tacticalModel.nodeFloors[node.id] ?? 0); setShowRawNode(false); }} onRaw={() => setShowRawNode(true)} />
          </>}
          {view === 'operations' && <OperationsView snapshot={snapshot} identity={identity} model={tacticalModel} onIdentity={() => { setIdentityOpen(true); void refreshIdentity(); }} onMap={(node) => { setSelectedNode(node); setActiveFloor(tacticalModel.nodeFloors[node.id] ?? 0); setView('map'); }} />}
          {view === 'intel' && <IntelLootView engagementId={engagementId} snapshot={snapshot} model={tacticalModel} onMap={(node) => { setSelectedNode(node); setActiveFloor(tacticalModel.nodeFloors[node.id] ?? 0); setView('map'); }} />}
          {view === 'activity' && <div className="activity-surface"><header><span>SIBYL EVENT STREAM</span><strong>{visibleEvents.length} VISIBLE EVENTS</strong></header><CentralTimeline events={visibleEvents} /></div>}
          {view === 'architecture' && <ArchitectureView snapshot={snapshot} identity={identity} />}
        </section>

        {view !== 'operations' && view !== 'intel' && view !== 'architecture' && <aside className={`operations-column ${showOperations ? 'open' : ''}`}>
          <button type="button" className="operations-close" onClick={() => setShowOperations(false)}>[X] CLOSE JOB RECORD</button>
          <div className="operator-lane-heading"><span>EXECUTION LANE</span><strong>{action ? action.status.replaceAll('_', ' ').toUpperCase() : 'MONITORING'}</strong></div>
          <ActionCard action={action} onReview={reviewAction} active={Boolean(action)} />
          <TrustCard node={focusedNode} connection={connection} edges={snapshot.edges} active={false} />
          <section className="regression-card">
            <div className="section-label"><span>REGRESSION WATCH</span><b>{snapshot.brief.regressions.length}</b></div>
            {snapshot.brief.regressions.length ? snapshot.brief.regressions.slice(-2).reverse().map((item) => <div className="regression-row" key={item.id}><span className="check">✓</span><div><strong>{item.name}</strong><small>{item.expected}</small></div></div>) : <EmptyState text="No regression checks yet" />}
          </section>
        </aside>}
      </div>
      {showOperations && <button type="button" className="ops-backdrop" aria-label="Close action queue" onClick={() => setShowOperations(false)} />}
      {identityOpen && <IdentityDrawer auth={auth} engagementId={engagementId} snapshot={identity} onRefresh={refreshIdentity} onClose={() => setIdentityOpen(false)} onAuthChanged={() => { setIdentityOpen(false); void refreshAuth(); }} onEngagementCreated={(created) => { setEngagements((current) => [...current, created]); setConnection('connecting'); setActiveFloor(0); setSessionFilter(''); setEngagementId(created.engagement_id); }} />}

      <footer className="statusbar">
        <span>ENGAGEMENT//<strong>{snapshot.engagement.engagement_id}</strong></span>
        <span>VIEW//<strong>{view.toUpperCase()}</strong></span>
        <span className="status-spacer" />
        {engagementId && <a href={`/api/engagements/${engagementId}/export`}>[ EXPORT::JSON ]</a>}
        <span>LAST_EVENT//<strong>{formatTime(snapshot.memory.last_event)}Z</strong></span>
        <span>EVENTS//<strong>{pad(snapshot.memory.event_count)}</strong></span>
      </footer>
    </main>
  );
}

function TacticalMap({ model, snapshot, identity, activeFloor, zoom, selectedNode, visibleNodeIds, sessionFilter, onFloor, onSession, onSelect, onEvent }: { model: TacticalModel; snapshot: Snapshot; identity: IdentitySnapshot; activeFloor: number; zoom: number; selectedNode: GraphNode | null; visibleNodeIds: Set<string>; sessionFilter: string; onFloor: (floor: number) => void; onSession: (session: string) => void; onSelect: (node: GraphNode) => void; onEvent: (event: MemoryEvent) => void }) {
  const floor = model.floors[activeFloor] || model.floors[0];
  const plan = model.plans[activeFloor] || model.plans[0];
  const rooms = model.rooms.filter((room) => room.floor === activeFloor);
  const roomByNode = Object.fromEntries(rooms.filter((room) => room.node).map((room) => [room.node!.id, room]));
  const knownRooms = rooms.filter((room) => room.node);
  const activeAgents = identity.agents.filter((agent) => agent.status === 'active');
  const feed = snapshot.events.filter((event) => !sessionFilter || event.h3retik_session_id === sessionFilter).slice(0, 5);
  const paths = snapshot.edges.flatMap((edge) => {
    const destination = roomByNode[edge.to];
    if (!destination) return [];
    const source = roomByNode[edge.from];
    const start = source ? doorPoint(source) : activeFloor === 0 ? { x: 50, y: 98 } : plan.hub;
    const end = doorPoint(destination);
    return [{ id: edge.id || `${edge.from}-${edge.type || 'related'}-${edge.to}`, points: routeThroughPlan(start, end, plan.hub, source?.door, destination.door), visible: visibleNodeIds.has(edge.to) }];
  });

  return <div className="tactical-console">
    <aside className="forward-base" aria-label="Operation base">
      <header><span>FORWARD BASE</span><strong>TEAM + COMPUTE</strong><small>OUTSIDE TARGET SPACE</small></header>
      <div className="base-counts"><div><strong>{pad(identity.members.length)}</strong><span>OPS</span></div><div><strong>{pad(activeAgents.length)}</strong><span>AGENTS</span></div><div><strong>{pad(identity.h3retik_sessions.length)}</strong><span>SESSIONS</span></div></div>
      <section className="base-workers"><span>CONNECTED WORKERS</span>{activeAgents.length ? activeAgents.slice(0, 4).map((agent) => <div key={agent.agent_id}><i /><strong>{agent.name}</strong><small>{agent.role || 'MCP WORKER'}</small></div>) : <p>NO AGENTS ONLINE</p>}</section>
      <section className="session-lenses"><span>SESSION LENS</span><button type="button" className={!sessionFilter ? 'active' : ''} onClick={() => onSession('')}><b>∞</b><div><strong>ALL SESSIONS</strong><small>COMBINED SIBYL STATE</small></div></button>{identity.h3retik_sessions.map((session) => <button type="button" className={sessionFilter === session.session_id ? 'active' : ''} key={session.session_id} onClick={() => onSession(session.session_id)}><b>H3</b><div><strong>{session.label}</strong><small>{session.status.toUpperCase()}</small></div></button>)}</section>
      <div className="sibyl-fabric"><i /><div><strong>SIBYL FABRIC</strong><small>{snapshot.memory.event_count} EVENTS RETAINED</small></div></div>
    </aside>

    <section className="target-map">
      <header className="target-map-heading"><div><span>{model.profile} TARGET / PROCEDURAL CUTAWAY</span><strong>{snapshot.engagement.target}</strong></div><div><b>{pad(knownRooms.length)}</b><span>KNOWN ROOMS</span></div><div><b>{String(model.seed).slice(-4).padStart(4, '0')}</b><span>MAP SEED</span></div></header>
      <div className="floor-stack" aria-label="Target layers">{model.floors.map((item, index) => <button type="button" aria-pressed={activeFloor === index} key={item.id} onClick={() => onFloor(index)}><b>{String(index + 1).padStart(2, '0')}</b><span>{item.label}<small>{item.subtitle}</small></span></button>)}</div>
      <div className="map-viewport">
        <div className="map-coordinates" aria-hidden="true"><span>N</span><i /><small>ORTHO / {floor.id}</small></div>
        <div className="floor-title"><span>CURRENT LAYER</span><strong>{floor.label}</strong><small>{floor.subtitle} / {plan.archetype}</small></div>
        <div className="building-stage" style={{ transform: `scale(${zoom})` }}>
          <div className="building-outline" aria-hidden="true" />
          {plan.corridors.map((corridor) => <div className="circulation-corridor" key={corridor.id} style={{ left: `${corridor.x}%`, top: `${corridor.y}%`, width: `${corridor.width}%`, height: `${corridor.height}%` }} aria-hidden="true"><i /></div>)}
          <svg className="attack-paths" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">{paths.map((path) => <polyline className={path.visible ? '' : 'filtered'} key={path.id} points={path.points} />)}</svg>
          {rooms.map((room) => room.node ? <button type="button" key={room.id} className={`tactical-room ${room.node.kind} ${selectedNode?.id === room.node.id ? 'selected' : ''} ${visibleNodeIds.has(room.node.id) ? '' : 'filtered'}`} style={{ left: `${room.x}%`, top: `${room.y}%`, width: `${room.width}%`, height: `${room.height}%` }} onClick={() => onSelect(room.node!)} aria-label={`Inspect room ${room.id}: ${room.node.label}`}>
            <span className="room-code">{room.id}</span><span className={`room-door ${room.door}`} aria-hidden="true" /><strong>{room.node.label}</strong><small>{room.node.meta}</small>
            {room.node.actor_name && <span className="room-operator"><i />{initials(room.node.actor_name)}<b>{room.node.actor_name}</b></span>}
            {room.node.h3retik_session_id && <span className="room-session">H3</span>}
          </button> : <div key={room.id} className="tactical-room fog" style={{ left: `${room.x}%`, top: `${room.y}%`, width: `${room.width}%`, height: `${room.height}%` }}><span className="room-code">{room.id}</span><span className={`room-door ${room.door}`} /><strong>UNMAPPED</strong><small>NO SIBYL EVIDENCE</small></div>)}
          <div className="vertical-core" style={{ left: `${plan.core.x}%`, top: `${plan.core.y}%`, width: `${plan.core.width}%`, height: `${plan.core.height}%` }}><span>▲▼</span><strong>CORE</strong><small>L{activeFloor + 1}</small></div>
          {activeFloor === 0 && <div className="entry-point"><i /><strong>ENTRY</strong><small>AUTHORIZED SCOPE</small></div>}
        </div>
        {sessionFilter && !knownRooms.some((room) => room.node?.h3retik_session_id === sessionFilter) && <div className="provenance-empty"><strong>NO SESSION-LINKED ROOMS ON THIS FLOOR</strong><span>The building remains stable; unmatched rooms are dimmed.</span></div>}
        <div className="map-legend"><span><i className="entity" />TARGET ENTITY</span><span><i className="confirmed" />LEGACY EVIDENCE</span><span><i className="path" />RELATIONSHIP</span></div>
      </div>
    </section>

    <aside className="live-ops-feed" aria-label="Live operation feed">
      <header><div><i />LIVE</div><strong>OPERATION FEED</strong><small>CURATED SIBYL EVENTS</small></header>
      <div>{feed.length ? feed.map((event) => <button type="button" key={event.id} className={eventTone(event.type)} onClick={() => onEvent(event)}><time>{formatTime(event.time)}</time><span>{event.actor_name || 'SYSTEM'}</span><strong>{event.title}</strong><small>{event.detail}</small>{event.object_id && <b>FOCUS ROOM →</b>}</button>) : <p>NO EVENTS MATCH THIS LENS</p>}</div>
      <footer><span>RAW STDOUT EXCLUDED</span><strong>PROVENANCE PRESERVED</strong></footer>
    </aside>
  </div>;
}

function buildTacticalModel(snapshot: Snapshot): TacticalModel {
  const seed = stableHash(snapshot.engagement.engagement_id || snapshot.engagement.target);
  const profile = targetProfile(snapshot);
  const nodes = snapshot.nodes.filter((node) => node.kind !== 'target');
  const grouped = profile.floors.map(() => [] as GraphNode[]);
  nodes.forEach((node) => {
    const preferred = floorForNode(node, profile.floors, seed);
    const available = profile.floors.findIndex((_, offset) => grouped[(preferred + offset) % profile.floors.length].length < 8);
    grouped[(preferred + Math.max(available, 0)) % profile.floors.length].push(node);
  });
  const rooms: TacticalRoom[] = [];
  const plans: TacticalPlan[] = [];
  const nodeFloors: Record<string, number> = {};
  grouped.forEach((floorNodes, floor) => {
    const generated = planFloor(seed, floor);
    const slots = generated.slots;
    plans.push(generated.plan);
    const occupied = new Set<number>();
    floorNodes.forEach((node) => {
      const affinity = node.h3retik_session_id || node.actor_id || node.kind;
      let slot = stableHash(`${affinity}:${floor}:${seed}`) % slots.length;
      while (occupied.has(slot)) slot = (slot + 1) % slots.length;
      occupied.add(slot);
      nodeFloors[node.id] = floor;
      const geometry = slots[slot];
      rooms.push({ node, id: `R-${floor + 1}${String(slot + 1).padStart(2, '0')}`, floor, ...geometry });
    });
    slots.forEach((geometry, slot) => {
      if (!occupied.has(slot)) rooms.push({ node: null, id: `R-${floor + 1}${String(slot + 1).padStart(2, '0')}`, floor, ...geometry });
    });
  });
  return { profile: profile.name, floors: profile.floors, rooms, plans, nodeFloors, seed };
}

function targetProfile(snapshot: Snapshot): { name: string; floors: TacticalFloor[] } {
  const text = `${snapshot.engagement.target} ${snapshot.engagement.scope} ${snapshot.engagement.allowed_lanes.join(' ')}`.toLowerCase();
  const make = (name: string, values: [string, string, string][]) => ({ name, floors: values.map(([id, label, subtitle]) => ({ id, label, subtitle })) });
  if (/\b(agent|llm|model|prompt|mcp|inference)\b/.test(text)) return make('AGENT SYSTEM', [['input', 'INPUT SURFACE', 'PROMPTS + CHANNELS'], ['reasoning', 'REASONING', 'POLICY + CONTROL'], ['tools', 'TOOLS', 'ACTIONS + INTEGRATIONS'], ['memory', 'MEMORY', 'STATE + RETRIEVAL']]);
  if (/\b(contract|evm|chain|wallet|defi|solidity)\b/.test(text)) return make('SMART CONTRACT', [['surface', 'SURFACE', 'CALLS + ENTRYPOINTS'], ['state', 'STATE', 'STORAGE + LOGIC'], ['privilege', 'PRIVILEGE', 'ROLES + GOVERNANCE'], ['assets', 'ASSETS', 'VALUE + IMPACT']]);
  if (/\b(android|ios|mobile|apk|ipa)\b/.test(text)) return make('MOBILE', [['client', 'CLIENT', 'UI + LOCAL CODE'], ['transport', 'TRANSPORT', 'NETWORK + API'], ['identity', 'IDENTITY', 'AUTH + SESSION'], ['storage', 'STORAGE', 'DATA + SECRETS']]);
  if (/\b(active directory|network|cidr|subnet|host|domain controller)\b/.test(text)) return make('NETWORK', [['external', 'EXTERNAL', 'EDGE + EXPOSURE'], ['identity', 'IDENTITY', 'USERS + ACCESS'], ['hosts', 'HOSTS', 'SERVICES + SYSTEMS'], ['privilege', 'PRIVILEGE', 'PATHS + CROWN JEWELS']]);
  if (/\b(repo|repository|source|codebase|package|binary|software)\b/.test(text)) return make('SOFTWARE', [['entry', 'ENTRYPOINTS', 'INPUT + INTERFACES'], ['trust', 'TRUST BOUNDARIES', 'AUTH + VALIDATION'], ['privilege', 'PRIVILEGED PATHS', 'CONTROL + EXECUTION'], ['data', 'DATA + IMPACT', 'SECRETS + OUTPUT']]);
  if (/\b(web|https?|api|domain|site|osint)\b/.test(text) || snapshot.engagement.target.includes('.')) return make('WEB APPLICATION', [['perimeter', 'PERIMETER', 'EDGE + DISCOVERY'], ['application', 'APPLICATION', 'ROUTES + SERVICES'], ['identity', 'IDENTITY', 'AUTH + SESSION'], ['data', 'DATA', 'STORAGE + IMPACT']]);
  return make('CUSTOM', [['surface', 'SURFACE', 'DISCOVERY + INPUT'], ['control', 'CONTROL', 'LOGIC + ACTIONS'], ['trust', 'TRUST', 'IDENTITY + BOUNDARIES'], ['impact', 'IMPACT', 'DATA + OUTCOMES']]);
}

function floorForNode(node: GraphNode, floors: TacticalFloor[], seed: number) {
  if (node.layer) {
    const layerAliases: Record<string, string[]> = {
      surface: ['surface', 'perimeter', 'external', 'entry', 'input', 'client'],
      perimeter: ['surface', 'perimeter', 'external', 'entry', 'input', 'client'],
      application: ['application', 'control', 'reasoning', 'tools', 'transport', 'state'],
      control: ['application', 'control', 'reasoning', 'tools', 'transport', 'state'],
      trust: ['trust', 'identity', 'privilege'],
      identity: ['trust', 'identity', 'privilege'],
      privilege: ['trust', 'identity', 'privilege'],
      infrastructure: ['hosts', 'infrastructure', 'tools'],
      data: ['data', 'assets', 'storage', 'impact', 'memory'],
      impact: ['data', 'assets', 'storage', 'impact', 'memory'],
    };
    const aliases = layerAliases[node.layer] || [node.layer];
    const explicit = floors.findIndex((floor) => aliases.some((alias) => `${floor.id} ${floor.label}`.toLowerCase().includes(alias)));
    if (explicit >= 0) return explicit;
  }
  const text = `${node.label} ${node.meta} ${JSON.stringify(node.detail)}`.toLowerCase();
  const keywordBands = [
    /edge|external|surface|endpoint|https?|port|route|entry|recon|discover|input|prompt|client/,
    /application|service|logic|state|control|reason|transport|host|tool|action|execute/,
    /auth|identity|session|token|role|permission|privilege|trust|governance|user/,
    /data|database|storage|secret|asset|impact|memory|output|crown|regression|finding/,
  ];
  const match = keywordBands.findIndex((pattern) => pattern.test(text));
  return match >= 0 ? Math.min(match, floors.length - 1) : stableHash(`${node.id}:${seed}`) % floors.length;
}

function planFloor(seed: number, floor: number): { plan: TacticalPlan; slots: Omit<TacticalRoom, 'node' | 'id' | 'floor'>[] } {
  const archetypes: TacticalPlan['archetype'][] = ['SPINE-H', 'SPINE-V', 'CROSS'];
  const archetype = archetypes[stableHash(`${seed}:plan:${floor}`) % archetypes.length];
  const hub = { x: 50, y: 50 };
  const core = { x: 46, y: 46, width: 8, height: 8 };
  const slots: Omit<TacticalRoom, 'node' | 'id' | 'floor'>[] = [];
  const corridors: TacticalCorridor[] = [];
  if (archetype === 'SPINE-H') {
    splitAxis(3, 97, 4, seed + floor * 17).forEach(({ start, size }) => slots.push({ x: start, y: 4, width: size, height: 38, door: 'south' }));
    splitAxis(3, 43, 2, seed + floor * 31).forEach(({ start, size }) => slots.push({ x: start, y: 58, width: size, height: 36, door: 'north' }));
    splitAxis(57, 97, 2, seed + floor * 47).forEach(({ start, size }) => slots.push({ x: start, y: 58, width: size, height: 36, door: 'north' }));
    corridors.push({ id: 'main', x: 3, y: 44, width: 94, height: 12 }, { id: 'egress', x: 46, y: 56, width: 8, height: 44 });
  } else if (archetype === 'SPINE-V') {
    splitAxis(4, 94, 4, seed + floor * 59).forEach(({ start, size }) => slots.push({ x: 3, y: start, width: 39, height: size, door: 'east' }));
    splitAxis(4, 94, 4, seed + floor * 71).forEach(({ start, size }) => slots.push({ x: 58, y: start, width: 39, height: size, door: 'west' }));
    corridors.push({ id: 'main', x: 44, y: 4, width: 12, height: 96 });
  } else {
    splitAxis(4, 42, 2, seed + floor * 83).forEach(({ start, size }) => slots.push({ x: 3, y: start, width: 39, height: size, door: 'east' }));
    splitAxis(4, 42, 2, seed + floor * 97).forEach(({ start, size }) => slots.push({ x: 58, y: start, width: 39, height: size, door: 'west' }));
    splitAxis(58, 94, 2, seed + floor * 109).forEach(({ start, size }) => slots.push({ x: 3, y: start, width: 39, height: size, door: 'east' }));
    splitAxis(58, 94, 2, seed + floor * 127).forEach(({ start, size }) => slots.push({ x: 58, y: start, width: 39, height: size, door: 'west' }));
    corridors.push({ id: 'vertical', x: 44, y: 4, width: 12, height: 96 }, { id: 'horizontal', x: 3, y: 44, width: 94, height: 12 });
  }
  return { plan: { archetype, corridors, hub, core }, slots };
}

function splitAxis(start: number, end: number, count: number, seed: number) {
  const gap = 1.7;
  const available = end - start - gap * (count - 1);
  const weights = Array.from({ length: count }, (_, index) => .88 + (stableHash(`${seed}:segment:${index}`) % 25) / 100);
  const total = weights.reduce((sum, weight) => sum + weight, 0);
  let cursor = start;
  return weights.map((weight, index) => {
    const size = index === count - 1 ? end - cursor : available * weight / total;
    const segment = { start: cursor, size };
    cursor += size + gap;
    return segment;
  });
}

function doorPoint(room: TacticalRoom) {
  if (room.door === 'north') return { x: room.x + room.width / 2, y: room.y };
  if (room.door === 'south') return { x: room.x + room.width / 2, y: room.y + room.height };
  if (room.door === 'east') return { x: room.x + room.width, y: room.y + room.height / 2 };
  return { x: room.x, y: room.y + room.height / 2 };
}

function routeThroughPlan(start: { x: number; y: number }, end: { x: number; y: number }, hub: { x: number; y: number }, sourceDoor: TacticalRoom['door'] | undefined, destinationDoor: TacticalRoom['door']) {
  const points = [start];
  if (sourceDoor === 'east' || sourceDoor === 'west') points.push({ x: hub.x, y: start.y });
  else if (sourceDoor) points.push({ x: start.x, y: hub.y });
  else if (start.x !== hub.x) points.push({ x: hub.x, y: start.y });
  points.push(hub);
  if (destinationDoor === 'east' || destinationDoor === 'west') points.push({ x: hub.x, y: end.y });
  else points.push({ x: end.x, y: hub.y });
  points.push(end);
  return points.filter((point, index) => index === 0 || point.x !== points[index - 1].x || point.y !== points[index - 1].y).map((point) => `${point.x},${point.y}`).join(' ');
}

function stableHash(value: string) { let hash = 2166136261; for (let index = 0; index < value.length; index += 1) { hash ^= value.charCodeAt(index); hash = Math.imul(hash, 16777619); } return hash >>> 0; }
function initials(value: string) { return value.split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase(); }

function OperatorOverview({ snapshot, identity, model, newEventCount, latestEvent, onFloor, onEvent, onOperations, onIntel, onActivity, onIdentity }: { snapshot: Snapshot; identity: IdentitySnapshot; model: TacticalModel; newEventCount: number; latestEvent: MemoryEvent | undefined; onFloor: (floor: number) => void; onEvent: (event: MemoryEvent) => void; onOperations: () => void; onIntel: () => void; onActivity: () => void; onIdentity: () => void }) {
  const activeAgents = identity.agents.filter((agent) => agent.status === 'active');
  const floorCounts = model.floors.map((floor, index) => ({ floor, index, rooms: model.rooms.filter((room) => room.floor === index && room.node), confirmed: model.rooms.filter((room) => room.floor === index && room.node?.kind === 'confirmed').length }));
  const attempts = snapshot.brief.recent_attempts.slice(-3).reverse();
  return <div className="briefing-deck">
    <section className="brief-command">
      <div className="card-index">01 / OPERATION BRIEF</div><span className="signal-label">LATEST MATERIAL CHANGE</span>
      <h2>{latestEvent ? latestEvent.title : 'Waiting for the first agent signal'}</h2>
      <p>{latestEvent?.detail || snapshot.brief.agent_instruction}</p>
      <div className="brief-kpis"><div><strong>{pad(newEventCount)}</strong><span>NEW SIGNALS</span></div><div><strong>{pad(snapshot.brief.findings.length)}</strong><span>FINDINGS</span></div><div><strong>{pad(snapshot.loot.length)}</strong><span>LOOT</span></div><div><strong>{pad(snapshot.brief.recent_attempts.length)}</strong><span>ATTACKS</span></div></div>
      <div className="brief-actions"><button type="button" onClick={() => onFloor(floorCounts.reduce((best, item) => item.rooms.length > floorCounts[best].rooms.length ? item.index : best, 0))}>ENTER HOTTEST FLOOR <b>→</b></button><button type="button" onClick={onActivity}>OPEN FULL LOG</button></div>
    </section>

    <section className="brief-force">
      <header><div><span className="signal-label">ACTIVE FORCE</span><h2>Agents + disposable compute</h2></div><button type="button" onClick={onIdentity}>MANAGE</button></header>
      <div className="force-stats"><div><strong>{pad(activeAgents.length)}</strong><span>AGENTS</span></div><div><strong>{pad(identity.h3retik_sessions.length)}</strong><span>H3 SESSIONS</span></div><div><strong>{pad(snapshot.brief.pending_actions.length)}</strong><span>JOBS</span></div></div>
      <div className="force-list">{activeAgents.length ? activeAgents.slice(0, 4).map((agent) => <div key={agent.agent_id}><i /><span><strong>{agent.name}</strong><small>{actorLocation(model, agent.agent_id)}</small></span><b>{agent.status.toUpperCase()}</b></div>) : <p>NO MCP WORKERS CONNECTED</p>}</div>
      <button type="button" className="surface-link" onClick={onOperations}>OPEN OPERATIONS <b>→</b></button>
    </section>

    <section className="brief-target">
      <header><div><span className="signal-label">TARGET PULSE</span><h2>{model.profile} cutaway</h2></div><strong>{snapshot.engagement.target}</strong></header>
      <div className="mini-floor-stack">{floorCounts.slice().reverse().map(({ floor, index, rooms, confirmed }) => <button type="button" key={floor.id} onClick={() => onFloor(index)}><b>L{index + 1}</b><span><strong>{floor.label}</strong><small>{rooms.length} mapped · {confirmed} confirmed · {model.plans[index].archetype}</small><i><em style={{ width: `${Math.max(5, rooms.length / 8 * 100)}%` }} /></i></span><u>→</u></button>)}</div>
    </section>

    <section className="brief-live">
      <header><div><i />LIVE</div><strong>OPERATION FEED</strong><button type="button" onClick={onActivity}>ALL</button></header>
      <div>{snapshot.events.slice(0, 5).map((event) => <button type="button" key={event.id} onClick={() => onEvent(event)} className={eventTone(event.type)}><time>{formatTime(event.time)}</time><span>{event.actor_name || 'SIBYL'}</span><strong>{event.title}</strong><small>{event.detail}</small></button>)}</div>
    </section>

    <section className="brief-intel confirmed"><div className="card-index">02 / FINDINGS</div><strong>{pad(snapshot.brief.findings.length)}</strong><h2>Confirmed findings</h2><p>{snapshot.brief.findings.at(-1)?.statement || 'No confirmed finding yet.'}</p><button type="button" onClick={onIntel}>OPEN INTEL <b>→</b></button></section>
    <section className="brief-intel loot"><div className="card-index">03 / LOOT</div><strong>{pad(snapshot.loot.length)}</strong><h2>Sealed artifacts</h2><div className="brief-loot-preview">{snapshot.loot.slice(0, 2).map((artifact) => <span key={artifact.id}><b>{artifact.type}</b><i>{artifact.sealed_preview}</i></span>)}</div><button type="button" onClick={onIntel}>OPEN LOOT LOCKER <b>→</b></button></section>
    <section className="brief-intel attacks"><div className="card-index">04 / ATTACK OUTCOMES</div><strong>{pad(snapshot.brief.recent_attempts.length)}</strong><h2>Attempts retained</h2><div>{attempts.length ? attempts.map((attempt) => { const outcome = classifyAttempt(attempt); return <span key={attempt.id} className={outcome.tone}><b>{outcome.label}</b><i>{attempt.approach}</i></span>; }) : <p>NO ATTEMPTS RECORDED</p>}</div><button type="button" onClick={onOperations}>OPEN LEDGER <b>→</b></button></section>
  </div>;
}

function OperationsView({ snapshot, identity, model, onIdentity, onMap }: { snapshot: Snapshot; identity: IdentitySnapshot; model: TacticalModel; onIdentity: () => void; onMap: (node: GraphNode) => void }) {
  const activeAgents = identity.agents.filter((agent) => agent.status === 'active');
  const attacks = [
    ...snapshot.brief.pending_actions.map((action) => ({ id: action.id, label: action.purpose, detail: action.command, outcome: action.status === 'human_required' ? 'STAGED' : action.status.replaceAll('_', ' ').toUpperCase(), tone: 'staged', actor: action.actor?.name || 'UNASSIGNED', session: action.h3retik_session_id || '', node: snapshot.nodes.find((node) => node.id === action.id) })),
    ...snapshot.brief.recent_attempts.slice().reverse().map((attempt) => { const result = classifyAttempt(attempt); return { id: attempt.id, label: attempt.approach, detail: attempt.outcome, outcome: result.label, tone: result.tone, actor: attempt.actor?.name || 'UNATTRIBUTED', session: '', node: snapshot.nodes.find((node) => node.id === attempt.id) }; }),
  ];
  return <div className="operations-deck">
    <header className="surface-heading"><div><span>03 / OPERATIONS</span><h2>Workers, sessions and attack outcomes</h2><p>Agent execution is normalized into Sibyl records instead of raw terminal noise.</p></div><button type="button" onClick={onIdentity}>MANAGE WORKERS</button></header>
    <div className="operations-kpis"><div><strong>{pad(activeAgents.length)}</strong><span>ACTIVE AGENTS</span></div><div><strong>{pad(identity.h3retik_sessions.length)}</strong><span>H3 SESSIONS</span></div><div><strong>{pad(snapshot.brief.pending_actions.length)}</strong><span>STAGED JOBS</span></div><div><strong>{pad(snapshot.brief.exhausted_paths.length)}</strong><span>EXHAUSTED</span></div></div>
    <section className="worker-roster"><header><span>WORKER ROSTER</span><strong>{activeAgents.length} ONLINE</strong></header><div>{identity.agents.length ? identity.agents.map((agent) => <article key={agent.agent_id}><i className={agent.status} /><div><strong>{agent.name}</strong><small>{agent.role || 'MCP RED-TEAM WORKER'}</small></div><span>{actorLocation(model, agent.agent_id)}</span><time>{agent.last_seen_at ? formatTime(agent.last_seen_at) : 'READY'}</time></article>) : <EmptyState text="Create an agent identity to begin" />}</div></section>
    <section className="session-pool"><header><span>H3RETIK COMPUTE</span><strong>{identity.h3retik_sessions.length} ATTACHED</strong></header><div>{identity.h3retik_sessions.length ? identity.h3retik_sessions.map((session) => { const jobs = snapshot.brief.pending_actions.filter((action) => action.h3retik_session_id === session.session_id).length; const runtime = session.seconds_left !== undefined ? `${Math.max(0, Math.ceil(session.seconds_left / 60))}M` : session.status.toUpperCase(); return <article key={session.session_id}><b>H3</b><div><strong>{session.label}</strong><small>{session.session_id} · {(session.lane || 'GENERAL').toUpperCase()}</small></div><span>{runtime}</span><em>{session.actions_remaining !== undefined ? `${session.actions_remaining} ACT` : `${jobs} JOB${jobs === 1 ? '' : 'S'}`}</em></article>; }) : <EmptyState text="No disposable compute sessions attached" />}</div></section>
    <section className="attack-ledger"><header><div><span>ATTACK LEDGER</span><strong>SUCCESS · INTEL · NO FINDING · FAILED · EXHAUSTED · BLOCKED</strong></div><b>{attacks.length} RECORDS</b></header><div>{attacks.length ? attacks.map((attack) => <button type="button" key={attack.id} className={attack.tone} disabled={!attack.node} onClick={() => attack.node && onMap(attack.node)}><span>{attack.outcome}</span><div><strong>{attack.label}</strong><small>{attack.detail}</small></div><b>{attack.actor}</b><em>{attack.session || 'NO SESSION PROVENANCE'}</em>{attack.node && <u>MAP →</u>}</button>) : <EmptyState text="No attack attempts have been recorded" />}</div></section>
  </div>;
}

function IntelLootView({ engagementId, snapshot, model, onMap }: { engagementId: string; snapshot: Snapshot; model: TacticalModel; onMap: (node: GraphNode) => void }) {
  return <div className="intel-loot-deck">
    <header className="surface-heading"><div><span>04 / INTEL + LOOT</span><h2>Findings and sealed telemetry</h2><p>Sibyl preserves provenance. Artifact payloads are fetched only after an explicit reveal.</p></div><div className="intel-head-stats"><b>{snapshot.brief.findings.length}<small>CONFIRMED</small></b><b>{snapshot.brief.open_hypotheses.length}<small>OPEN</small></b><b>{snapshot.loot.length}<small>LOOT</small></b></div></header>
    <section className="findings-matrix"><header><span>FINDING TELEMETRY</span><strong>CONFIDENCE + PROVENANCE</strong></header><div className="finding-columns"><div className="confirmed"><span>CONFIRMED</span>{snapshot.brief.findings.map((item) => { const node = snapshot.nodes.find((candidate) => candidate.id === item.id || item.entity_ids?.includes(candidate.id)); return <button type="button" key={item.id} disabled={!node} onClick={() => node && onMap(node)}><i /><strong>{item.statement}</strong><small>{Math.round(item.confidence * 100)}% · {item.source}</small>{node && <b>{nodeLocation(model, node.id)}</b>}</button>; })}</div><div className="hypothesis"><span>OPEN HYPOTHESES</span>{snapshot.brief.open_hypotheses.map((item) => { const node = snapshot.nodes.find((candidate) => candidate.id === item.id); return <button type="button" key={item.id} disabled={!node} onClick={() => node && onMap(node)}><i /><strong>{item.statement}</strong><small>NEEDS CORROBORATION</small>{node && <b>{nodeLocation(model, node.id)}</b>}</button>; })}</div><div className="regression"><span>REGRESSION WATCH</span>{snapshot.brief.regressions.map((item) => { const node = snapshot.nodes.find((candidate) => candidate.id === item.id); return <button type="button" key={item.id} disabled={!node} onClick={() => node && onMap(node)}><i /><strong>{item.name}</strong><small>{item.expected}</small>{node && <b>{nodeLocation(model, node.id)}</b>}</button>; })}</div></div></section>
    <section className="loot-locker"><header><div><span>LOOT LOCKER</span><strong>ON-DEMAND TELEMETRY / REDACTED BY DEFAULT</strong></div><b>{snapshot.loot.length} ARTIFACTS</b></header><div>{snapshot.loot.length ? snapshot.loot.map((artifact) => { const room = snapshot.nodes.find((node) => artifact.entity_ids?.includes(node.id)); return <LootCard key={artifact.id} artifact={artifact} engagementId={engagementId} room={room} onMap={onMap} />; }) : <EmptyState text="No evidence-bearing artifacts have been collected" />}</div></section>
  </div>;
}

function LootCard({ artifact, engagementId, room, onMap }: { artifact: LootArtifact; engagementId: string; room?: GraphNode; onMap: (node: GraphNode) => void }) {
  const [telemetry, setTelemetry] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const reveal = async () => {
    if (telemetry) { setTelemetry(null); return; }
    setBusy(true); setError('');
    try {
      if (artifact.preview_telemetry) setTelemetry(artifact.preview_telemetry);
      else {
        if (!engagementId) throw new Error('artifact preview unavailable');
        const response = await fetch(`/api/engagements/${encodeURIComponent(engagementId)}/loot/${encodeURIComponent(artifact.id)}`, { cache: 'no-store' });
        const result = await response.json() as Record<string, unknown>;
        if (!response.ok) throw new Error(String(result.error || 'reveal failed'));
        setTelemetry(recordOf(result.telemetry));
      }
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  return <article className={`loot-card ${artifact.sensitive ? 'sensitive' : ''} ${telemetry ? 'revealed' : 'sealed'}`}><header><span>{artifact.type}</span><b>{artifact.assurance?.toUpperCase() || (artifact.sensitive ? 'SENSITIVE' : 'COLLECTED')}</b></header><h3>{artifact.label}</h3>{artifact.entity_labels?.length ? <p className="artifact-location">ROOM// {artifact.entity_labels.join(' / ')}</p> : null}<dl><div><dt>SOURCE</dt><dd>{artifact.source}</dd></div><div><dt>JOB</dt><dd>{artifact.job_id || 'MEMORY'}</dd></div><div><dt>SIZE</dt><dd>{formatBytes(artifact.size_bytes)}</dd></div><div><dt>SHA</dt><dd>{artifact.integrity}</dd></div></dl><div className="telemetry-vault"><span>{telemetry ? 'DISCLOSED TELEMETRY' : 'SEALED PREVIEW'}</span><pre>{telemetry ? JSON.stringify(telemetry, null, 2) : artifact.sealed_preview}</pre></div>{error && <p>{error.toUpperCase()}</p>}<button type="button" disabled={busy || !artifact.has_reveal} aria-expanded={Boolean(telemetry)} onClick={reveal}>{busy ? 'FETCHING…' : telemetry ? 'HIDE TELEMETRY' : 'CLICK TO REVEAL'} <b>→</b></button>{room && <button type="button" className="artifact-map-link" onClick={() => onMap(room)}>LOCATE ROOM <b>↗</b></button>}<footer>Fetched on demand · never embedded in overview</footer></article>;
}

function PasskeyGate({ auth, inviteToken, onBypass, onAuthenticated }: { auth: AuthStatus | null; inviteToken: string; onBypass: () => void; onAuthenticated: () => void }) {
  const [displayName, setDisplayName] = useState('Operator');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const setup = Boolean(inviteToken) || auth?.state === 'setup';
  const act = async () => {
    setBusy(true);
    setError('');
    try {
      if (setup) await registerPasskey(displayName, inviteToken);
      else await authenticatePasskey();
      onAuthenticated();
    } catch (cause) {
      setError(friendlyPasskeyError(cause));
    } finally {
      setBusy(false);
    }
  };
  return <section className="auth-gate" aria-label="Passkey access">
    <div className="auth-frame">
      <span className="auth-kicker">H1DR4//IDENTITY GATE</span>
      <h1>{!auth ? 'CHECKING LOCAL IDENTITY' : setup ? inviteToken ? 'JOIN SHARED ENGAGEMENT' : 'CLAIM THIS CONSOLE' : 'UNLOCK ATTACKGRAPH'}</h1>
      <p>{setup ? 'Save an operator passkey with your device or password manager. No account password, recovery phrase, or on-chain identity.' : 'Continue with a saved passkey on this device, or choose another device to scan the system QR.'}</p>
      {setup && <label><span>DISPLAY NAME</span><input value={displayName} onChange={(event) => setDisplayName(event.target.value)} maxLength={80} autoFocus /></label>}
      {auth && <button className="passkey-primary" type="button" disabled={busy || (setup && !displayName.trim())} onClick={act}>{busy ? '[ WAITING FOR SYSTEM ]' : setup ? '[ SAVE PASSKEY ]' : '[ CONTINUE WITH PASSKEY ]'}</button>}
      {error && <p className="auth-error">ERROR// {error}</p>}
      {setup && !inviteToken && auth?.mode !== 'passkey' && <button className="auth-bypass" type="button" onClick={onBypass}>CONTINUE LOCAL / SECURE LATER</button>}
      <small>Your device or passkey provider handles verification. Any nearby-device QR is generated by the operating system and is never stored by H1DR4.</small>
    </div>
  </section>;
}

function IdentityDrawer({ auth, engagementId, snapshot, onRefresh, onClose, onAuthChanged, onEngagementCreated }: { auth: AuthStatus | null; engagementId: string; snapshot: IdentitySnapshot; onRefresh: () => Promise<void>; onClose: () => void; onAuthChanged: () => void; onEngagementCreated: (engagement: Engagement) => void }) {
  const [agentName, setAgentName] = useState('Recon Worker');
  const [newAgent, setNewAgent] = useState<Record<string, unknown> | null>(null);
  const [invite, setInvite] = useState<Record<string, unknown> | null>(null);
  const [sessionId, setSessionId] = useState('');
  const [sessionLabel, setSessionLabel] = useState('Kali pool');
  const [sessionLane, setSessionLane] = useState('web');
  const [extensionReceipt, setExtensionReceipt] = useState<Record<string, unknown> | null>(null);
  const [engagementTitle, setEngagementTitle] = useState('New operation');
  const [target, setTarget] = useState('');
  const [scope, setScope] = useState('Explicitly authorized target');
  const [mode, setMode] = useState('manual_only');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const humans = snapshot.members.filter((member) => member.principal_type === 'human');

  const post = async (path: string, body: Record<string, unknown>) => {
    const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const result = await response.json() as Record<string, unknown>;
    if (!response.ok) throw new Error(String(result.error || 'request_failed'));
    return result;
  };
  const createAgent = async () => {
    setBusy('agent'); setError('');
    try { setNewAgent(await post('/api/agents', { engagement_id: engagementId, name: agentName })); await onRefresh(); }
    catch (cause) { setError(String(cause)); } finally { setBusy(''); }
  };
  const createEngagement = async () => {
    setBusy('engagement'); setError('');
    try {
      const created = await post('/api/engagements', { title: engagementTitle, target, scope, mode, allowed_lanes: ['web', 'local', 'osint'] });
      onEngagementCreated(created as unknown as Engagement);
    } catch (cause) { setError(String(cause)); } finally { setBusy(''); }
  };
  const createInvite = async () => {
    setBusy('invite'); setError('');
    try { setInvite(await post('/api/invites', { engagement_id: engagementId, role: 'operator', hours: 24 })); }
    catch (cause) { setError(String(cause)); } finally { setBusy(''); }
  };
  const bindSession = async () => {
    setBusy('session'); setError('');
    try { await post('/api/h3retik-sessions', { engagement_id: engagementId, session_id: sessionId, label: sessionLabel, lane: sessionLane }); setSessionId(''); await onRefresh(); }
    catch (cause) { setError(String(cause)); } finally { setBusy(''); }
  };
  const extendSession = async (session: H3retikSession) => {
    setBusy(`extend:${session.session_id}`); setError('');
    try {
      setExtensionReceipt(await post(`/api/h3retik-sessions/${session.session_id}/extension-receipts`, { engagement_id: engagementId, minutes: 15, actions: 5, asset: 'USDC' }));
    } catch (cause) { setError(String(cause)); } finally { setBusy(''); }
  };
  const syncExtension = async () => {
    const receipt = extensionReceipt?.receipt as Record<string, unknown> | undefined;
    if (!receipt?.receipt_id) return;
    setBusy('extension-sync'); setError('');
    try {
      const synced = await post(`/api/h3retik-receipts/${String(receipt.receipt_id)}/sync`, { engagement_id: engagementId });
      setExtensionReceipt(synced);
      await onRefresh();
    } catch (cause) { setError(String(cause)); } finally { setBusy(''); }
  };
  const secureConsole = async () => {
    setBusy('passkey'); setError('');
    try { await registerPasskey(auth?.user?.display_name || 'Operator', ''); onAuthChanged(); }
    catch (cause) { setError(friendlyPasskeyError(cause)); } finally { setBusy(''); }
  };
  const logout = async () => { await fetch('/api/auth/logout', { method: 'POST' }); onAuthChanged(); };
  return <><button type="button" className="identity-backdrop" aria-label="Close identity panel" onClick={onClose} /><aside className="identity-drawer">
    <header><div><span>{'// CONTROL PLANE'}</span><h2>IDENTITY + WORKERS</h2></div><button type="button" onClick={onClose}>[X]</button></header>
    <section className="identity-status"><span>HUMAN ACCESS</span><strong>{auth?.authenticated ? auth.user?.display_name : auth?.passkey_count ? 'LOCKED' : 'LOCAL / UNCLAIMED'}</strong><small>{auth?.passkey_count ? `${auth.passkey_count} PASSKEY${auth.passkey_count === 1 ? '' : 'S'} REGISTERED` : 'NO PASSWORD DATABASE'}</small>{!auth?.passkey_count && <button type="button" onClick={secureConsole} disabled={busy === 'passkey'}>[ SET UP PASSKEY ]</button>}{auth?.authenticated && <button type="button" onClick={logout}>[ LOCK CONSOLE ]</button>}</section>

    {!engagementId && <section className="engagement-bootstrap"><div className="drawer-label"><span>BOOTSTRAP ENGAGEMENT</span><b>00</b></div><p className="drawer-note">Create the shared memory boundary before connecting workers.</p><div className="bootstrap-fields"><input value={engagementTitle} onChange={(event) => setEngagementTitle(event.target.value)} placeholder="OPERATION NAME" /><input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="AUTHORIZED TARGET" /><input value={scope} onChange={(event) => setScope(event.target.value)} placeholder="SCOPE" /><select value={mode} onChange={(event) => setMode(event.target.value)}><option value="manual_only">MANUAL / ASSISTED</option><option value="local_lab">LOCAL LAB</option><option value="autonomous_lab">AUTONOMOUS LAB</option></select><button type="button" onClick={createEngagement} disabled={!engagementTitle.trim() || !target.trim() || !scope.trim() || busy === 'engagement'}>[ OPEN ENGAGEMENT ]</button></div></section>}

    <section><div className="drawer-label"><span>TEAM</span><b>{humans.length}</b></div>{humans.length ? humans.map((member) => <div className="identity-row" key={member.principal_id}><i className="human" /><div><strong>{member.name}</strong><small>HUMAN :: {member.role.toUpperCase()}</small></div></div>) : <p className="drawer-empty">Local operator only</p>}<button type="button" className="drawer-action" onClick={createInvite} disabled={!engagementId || busy === 'invite'}>[ + ] CREATE 24H SINGLE-USE INVITE</button>{invite && <SecretBox title="INVITE URL / SHOWN ONCE" value={String(invite.invite_url || '')} />}</section>

    <section><div className="drawer-label"><span>AGENT IDENTITIES</span><b>{snapshot.agents.length}</b></div>{snapshot.agents.map((agent) => <div className="identity-row agent" key={agent.agent_id}><i /><div><strong>{agent.name}</strong><small>{agent.agent_id} :: {agent.status.toUpperCase()} :: TOKEN …{agent.token_hint}</small></div>{agent.status === 'active' && <button type="button" onClick={async () => { await post(`/api/agents/${agent.agent_id}/revoke`, { engagement_id: engagementId }); await onRefresh(); }}>REVOKE</button>}</div>)}<div className="drawer-form"><input value={agentName} onChange={(event) => setAgentName(event.target.value)} placeholder="AGENT NAME" /><button type="button" onClick={createAgent} disabled={!engagementId || !agentName.trim() || busy === 'agent'}>[ CREATE ]</button></div>{newAgent && <><SecretBox title="AGENT TOKEN / SHOWN ONCE" value={String(newAgent.token || '')} /><SecretBox title="MCP CONFIG" value={JSON.stringify(newAgent.mcp_config, null, 2)} multiline /></>}</section>

    <section><div className="drawer-label"><span>H3RETIK SESSION POOL</span><b>{snapshot.h3retik_sessions.length}</b></div>{snapshot.h3retik_sessions.map((session) => <div className="identity-row" key={session.binding_id}><i className="session" /><div><strong>{session.label}</strong><small>{session.session_id} :: {(session.lane || 'GENERAL').toUpperCase()} :: {session.status.toUpperCase()}{session.actions_remaining !== undefined ? ` :: ${session.actions_remaining} ACT` : ''}</small></div>{session.extendable !== false && <button type="button" onClick={() => { void extendSession(session); }} disabled={busy === `extend:${session.session_id}`}>TOP UP</button>}</div>)}<div className="drawer-form session"><input value={sessionLabel} onChange={(event) => setSessionLabel(event.target.value)} placeholder="LABEL" /><select value={sessionLane} onChange={(event) => setSessionLane(event.target.value)}><option value="web">WEB</option><option value="local">GENERAL</option><option value="osint">OSINT</option><option value="onchain">ONCHAIN</option></select><input value={sessionId} onChange={(event) => setSessionId(event.target.value)} placeholder="H3 SESSION ID" /><button type="button" onClick={bindSession} disabled={!sessionId.trim() || busy === 'session'}>[ ATTACH ]</button></div>{extensionReceipt && <ExtensionReceiptCard value={extensionReceipt} busy={busy === 'extension-sync'} onSync={() => { void syncExtension(); }} />}<small className="drawer-note">One workspace can combine many disposable sessions. Top-up creates a payable 15 minute / 5 action receipt; no charge occurs until you fund it.</small></section>
    {error && <p className="drawer-error">ERROR// {error.replace('Error: ', '')}</p>}
  </aside></>;
}

function SecretBox({ title, value, multiline = false }: { title: string; value: string; multiline?: boolean }) {
  const [copied, setCopied] = useState(false);
  return <div className={`secret-box ${multiline ? 'multiline' : ''}`}><span>{title}</span><pre>{value}</pre><button type="button" onClick={() => { void navigator.clipboard.writeText(value); setCopied(true); window.setTimeout(() => setCopied(false), 1200); }}>{copied ? 'COPIED' : 'COPY'}</button></div>;
}

function ExtensionReceiptCard({ value, busy, onSync }: { value: Record<string, unknown>; busy: boolean; onSync: () => void }) {
  const receipt = (value.receipt || {}) as Record<string, unknown>;
  const payment = (receipt.payment || {}) as Record<string, unknown>;
  const status = String(receipt.status || 'pending').toUpperCase();
  const amount = `${String(payment.minimum_amount || receipt.amount_usdc || '?')} ${String(payment.send_asset || receipt.asset || 'USDC')}`;
  return <div className="extension-receipt"><header><span>SESSION TOP-UP</span><b>{status}</b></header><strong>{amount} ON BASE</strong><small>+{String(receipt.minutes || 0)} MIN / +{String(receipt.actions || 0)} ACTIONS</small><SecretBox title="FUNDING ADDRESS" value={String(receipt.funding_address || '')} /><button type="button" onClick={onSync} disabled={busy || status === 'PAID'}>{status === 'PAID' ? '[ APPLIED ]' : busy ? '[ CHECKING BASE ]' : '[ SYNC PAYMENT ]'}</button></div>;
}

async function registerPasskey(displayName: string, inviteToken: string) {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('passkeys_not_supported');
  const options = await apiJson('/api/auth/passkey/register/options', { display_name: displayName, invite_token: inviteToken });
  const credential = await navigator.credentials.create({ publicKey: decodeCreationOptions(options.publicKey as Record<string, unknown>) });
  if (!(credential instanceof PublicKeyCredential)) throw new Error('passkey_creation_cancelled');
  await apiJson('/api/auth/passkey/register/verify', { challenge_id: options.challenge_id, credential: serializeCredential(credential) });
}

async function authenticatePasskey() {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('passkeys_not_supported');
  const options = await apiJson('/api/auth/passkey/login/options', {});
  const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(options.publicKey as Record<string, unknown>) });
  if (!(credential instanceof PublicKeyCredential)) throw new Error('passkey_authentication_cancelled');
  await apiJson('/api/auth/passkey/login/verify', { challenge_id: options.challenge_id, credential: serializeCredential(credential) });
}

async function apiJson(path: string, body: Record<string, unknown>) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const result = await response.json() as Record<string, unknown>;
  if (!response.ok) throw new Error(String(result.error || 'request_failed'));
  return result;
}

function decodeCreationOptions(value: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const copy = { ...value, challenge: fromBase64Url(String(value.challenge || '')), user: { ...(value.user as Record<string, unknown>), id: fromBase64Url(String((value.user as Record<string, unknown>)?.id || '')) } } as Record<string, unknown>;
  copy.excludeCredentials = ((value.excludeCredentials as Record<string, unknown>[] | undefined) || []).map((item) => ({ ...item, id: fromBase64Url(String(item.id || '')) }));
  return copy as unknown as PublicKeyCredentialCreationOptions;
}

function decodeRequestOptions(value: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  return { ...value, challenge: fromBase64Url(String(value.challenge || '')), allowCredentials: ((value.allowCredentials as Record<string, unknown>[] | undefined) || []).map((item) => ({ ...item, id: fromBase64Url(String(item.id || '')) })) } as unknown as PublicKeyCredentialRequestOptions;
}

function serializeCredential(credential: PublicKeyCredential) {
  const response = credential.response;
  const base = { id: credential.id, rawId: toBase64Url(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults() };
  if (response instanceof AuthenticatorAttestationResponse) return { ...base, response: { clientDataJSON: toBase64Url(response.clientDataJSON), attestationObject: toBase64Url(response.attestationObject), transports: response.getTransports?.() || [] } };
  const assertion = response as AuthenticatorAssertionResponse;
  return { ...base, response: { clientDataJSON: toBase64Url(assertion.clientDataJSON), authenticatorData: toBase64Url(assertion.authenticatorData), signature: toBase64Url(assertion.signature), userHandle: assertion.userHandle ? toBase64Url(assertion.userHandle) : null } };
}

function fromBase64Url(value: string) { const normalized = value.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(value.length / 4) * 4, '='); const binary = window.atob(normalized); return Uint8Array.from(binary, (char) => char.charCodeAt(0)); }
function toBase64Url(value: ArrayBuffer) { const bytes = new Uint8Array(value); let binary = ''; bytes.forEach((byte) => { binary += String.fromCharCode(byte); }); return window.btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
function friendlyPasskeyError(cause: unknown) { const message = cause instanceof Error ? cause.message : String(cause); if (message.includes('NotAllowedError')) return 'DEVICE PROMPT CANCELLED OR TIMED OUT'; if (message.includes('not supported')) return 'THIS BROWSER DOES NOT SUPPORT PASSKEYS'; return message.replaceAll('_', ' ').toUpperCase(); }

function EmptyState({ text }: { text: string }) { return <p className="empty-state">{text}</p>; }

function ActionCard({ action, onReview, active }: { action: Action | null; onReview: () => void; active: boolean }) {
  const status = action?.status === 'human_required' ? 'POLICY::HOLD' : action?.status.replaceAll('_', '::').toUpperCase();
  return <section className={`action-card focus-zone ${active ? 'is-active' : ''}`}><div className="section-label"><span>JOB::RECORD</span><b>[{action ? '01' : '00'}]</b></div>{action ? <><div className="action-id"><span>{action.id.toUpperCase()}</span><em>{status}</em></div><h2>{action.purpose}</h2><div className="execution-notice"><strong>AGENT EXECUTION</strong><span>Dashboard records; workers execute.</span></div><code><b>$</b> {action.command}<i aria-hidden="true" /></code><dl><div><dt>LANE//</dt><dd>{action.lane.toUpperCase()}</dd></div><div><dt>RUNTIME//</dt><dd>≤ {action.max_minutes} MIN</dd></div><div><dt>BUDGET//</dt><dd>{action.budget_usdc.toFixed(2)} USDC</dd></div></dl><button type="button" className="review-action" onClick={onReview}>[ ENTER ] LOCATE ON MAP</button></> : <EmptyState text="No staged agent jobs" />}</section>;
}

function SelectedNodeDetail({ node, edges, nodes, onSelect, onRaw }: { node: GraphNode | null; edges: GraphEdge[]; nodes: GraphNode[]; onSelect: (node: GraphNode) => void; onRaw: () => void }) {
  if (!node) return <section className="selected-detail"><div><span>SELECTED NODE</span><strong>No node matches the current filter</strong></div></section>;
  const detail = recordOf(node.detail);
  const findings = arrayOfRecords(detail.findings);
  const loot = arrayOfRecords(detail.loot);
  const links = edges.flatMap((edge) => {
    if (edge.from !== node.id && edge.to !== node.id) return [];
    const otherId = edge.from === node.id ? edge.to : edge.from;
    const other = nodes.find((candidate) => candidate.id === otherId);
    return other ? [{ edge, other }] : [];
  });
  return <section className="selected-detail" aria-label="Selected room intelligence"><div className="selected-main"><span>SELECTED ROOM</span><strong>{node.label}</strong><small>{node.meta}</small></div><div><span>ENTITY</span><strong>{(node.entity_type || node.kind).toUpperCase()}</strong></div><div><span>FINDINGS</span><strong>{findings.length} ATTACHED</strong></div><div><span>LOOT</span><strong>{loot.length} ARTIFACT{loot.length === 1 ? '' : 'S'}</strong></div><div><span>GRAPH</span><strong>{links.length} LINK{links.length === 1 ? '' : 'S'}</strong></div><button type="button" onClick={onRaw}>RAW RECORD</button>{links.length ? <div className="room-connections"><span>CONNECTED ROOMS</span>{links.map(({ edge, other }) => <button type="button" key={edge.id || `${edge.from}-${edge.to}-${edge.type}`} onClick={() => onSelect(other)}><b>{(edge.label || edge.type || 'related').toUpperCase()}</b><strong>{other.label}</strong><small>{edge.from === node.id ? 'OUTBOUND' : 'INBOUND'} →</small></button>)}</div> : null}{findings.length || loot.length ? <div className="room-evidence"><span>ROOM INTEL</span>{findings.slice(0, 2).map((finding) => <article key={String(finding.id)}><b>FINDING</b><strong>{String(finding.title || 'Recorded finding')}</strong><small>{String(finding.assurance || 'asserted').toUpperCase()}</small></article>)}{loot.slice(0, 2).map((artifact) => <article key={String(artifact.id)}><b>LOOT</b><strong>{String(artifact.label || 'Collected artifact')}</strong><small>{String(artifact.assurance || 'asserted').toUpperCase()}</small></article>)}</div> : null}</section>;
}

function TrustCard({ node, connection, edges, active }: { node: GraphNode | null; connection: Connection; edges: { from: string; to: string }[]; active: boolean }) {
  const detail = recordOf(node?.detail);
  const source = textField(detail, 'source') || textField(detail, 'job_id') || 'Sibyl memory';
  const confidence = numberField(detail, 'confidence');
  const related = node ? edges.filter((edge) => edge.from === node.id || edge.to === node.id).length : 0;
  return <section className={`trust-card focus-zone ${active ? 'is-active' : ''}`}><div className="section-label"><span>TRUST::SIGNALS</span><b>{connection === 'live' ? 'LIVE' : 'LOCAL'}</b></div><dl><div><dt>SELECTED//</dt><dd>{node?.label || 'NONE'}</dd></div><div><dt>SOURCE//</dt><dd>{source}</dd></div><div><dt>CONFIDENCE//</dt><dd>{confidence === null ? node?.meta || 'UNRATED' : `${Math.round(confidence * 100)}%`}</dd></div><div><dt>RELATIONSHIPS//</dt><dd>{related} LINK{related === 1 ? '' : 'S'}</dd></div></dl></section>;
}

function CentralTimeline({ events }: { events: MemoryEvent[] }) {
  return <div className="central-timeline">{events.length ? events.map((event, index) => <div className="central-event" key={event.id}><span>{String(index + 1).padStart(2, '0')}</span><time>{formatDate(event.time)} · {formatTime(event.time)}</time><i className={eventTone(event.type)} /><div><strong>{event.title}</strong><p>{event.detail}</p>{event.actor_name && <small>WORKER// {event.actor_name}</small>}</div></div>) : <EmptyState text="No Sibyl events recorded" />}</div>;
}

function NodeInspector({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  return <aside className="node-inspector"><button type="button" onClick={onClose} aria-label="Close node details">[X]</button><span>┌─ NODE::INSPECT / {node.meta}</span><h2>&gt; {node.label}</h2><pre>{JSON.stringify(node.detail, null, 2)}</pre><small>└─ EOF</small></aside>;
}

function recordOf(value: unknown): Record<string, unknown> { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function arrayOfRecords(value: unknown) { return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object' && !Array.isArray(item)) : []; }
function textField(record: Record<string, unknown>, key: string) { const value = record[key]; return typeof value === 'string' ? value : ''; }
function numberField(record: Record<string, unknown>, key: string) { const value = record[key]; return typeof value === 'number' && Number.isFinite(value) ? value : null; }

function nodeLocation(model: TacticalModel, nodeId: string) {
  const room = model.rooms.find((candidate) => candidate.node?.id === nodeId);
  return room ? `${model.floors[room.floor].label} / ${room.id}` : 'BASE / UNMAPPED';
}

function actorLocation(model: TacticalModel, actorId: string) {
  const room = model.rooms.find((candidate) => candidate.node?.actor_id === actorId);
  return room ? `${model.floors[room.floor].label} / ${room.id}` : 'BASE / READY';
}

function classifyAttempt(attempt: Attempt) {
  const text = `${attempt.approach} ${attempt.outcome}`.toLowerCase();
  if (attempt.exhausted) return { label: 'EXHAUSTED', tone: 'exhausted' };
  if (/blocked|denied|scope|timeout|budget/.test(text)) return { label: 'BLOCKED', tone: 'blocked' };
  if (/found|confirmed|success|vulnerab|exposed/.test(text)) return { label: 'SUCCESS / INTEL', tone: 'success' };
  if (/no finding|negative|not vulnerable|expected behavior/.test(text)) return { label: 'NO FINDING', tone: 'no-finding' };
  if (/error|failed|failure|unreachable|crash/.test(text)) return { label: 'FAILED', tone: 'failed' };
  return { label: 'INTEL', tone: 'intel' };
}

function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`; return `${(value / 1024 / 1024).toFixed(1)} MB`; }

function eventTone(type: string) { if (type.includes('hypothesis')) return 'hypothesis'; if (type.includes('attempt')) return 'exhausted'; if (type.includes('engagement') || type.includes('recall')) return 'memory'; return 'confirmed'; }
function pad(value: number) { return String(value).padStart(2, '0'); }
function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? '—' : date.toLocaleTimeString('en-GB', { timeZone: 'UTC', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? 'UNKNOWN' : date.toLocaleDateString('en-US', { timeZone: 'UTC', month: 'short', day: '2-digit' }).toUpperCase(); }
