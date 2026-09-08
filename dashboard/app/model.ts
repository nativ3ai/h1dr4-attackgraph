export type Engagement = {
  engagement_id: string;
  title: string;
  target: string;
  mode: string;
  scope: string;
  target_allowlist: string[];
  allowed_lanes: string[];
  rules: string[];
  operator_id?: string;
};

export type Actor = { id: string; name: string; type: 'human' | 'agent' | string };

export type Observation = {
  id: string;
  statement: string;
  source: string;
  confidence: number;
  kind: string;
  actor?: Actor;
  evidence?: Record<string, unknown>;
  entity_ids?: string[];
  presentation?: Record<string, string>;
  recorded_at?: string;
};

export type Hypothesis = { id: string; statement: string; status: string; actor?: Actor };
export type Attempt = { id: string; approach: string; outcome: string; exhausted: boolean; actor?: Actor };
export type Action = {
  id: string;
  target: string;
  lane: string;
  command: string;
  purpose: string;
  risk: string;
  max_minutes: number;
  budget_usdc: number;
  h3retik_session_id?: string;
  status: string;
  actor?: Actor;
};
export type Regression = { id: string; name: string; check: string; expected: string; actor?: Actor };

export type GraphNode = {
  id: string;
  label: string;
  meta: string;
  kind: string;
  x: number;
  y: number;
  detail: unknown;
  actor_id?: string;
  actor_name?: string;
  h3retik_session_id?: string;
  job_id?: string;
  entity_type?: string;
  layer?: string;
};

export type GraphEdge = { id?: string; from: string; to: string; type?: string; label?: string };
export type MemoryEvent = { id: string; time: string; type: string; title: string; detail: string; actor_id?: string; actor_name?: string; actor_type?: string; object_id?: string; h3retik_session_id?: string; job_id?: string };

export type LootArtifact = {
  id: string;
  label: string;
  type: string;
  source: string;
  sensitive: boolean;
  sealed_preview: string;
  has_reveal: boolean;
  size_bytes: number;
  integrity: string;
  recorded_at: string;
  actor_id?: string;
  actor_name?: string;
  job_id?: string;
  assurance?: string;
  entity_ids?: string[];
  entity_labels?: string[];
  finding_ids?: string[];
  preview_telemetry?: Record<string, unknown>;
};

export type EngagementPostureReason = {
  record_id: string;
  signal: string;
  label: string;
  summary: string;
  source: string;
  actor_id?: string;
  actor_name?: string;
  recorded_at: string;
  rank: number;
};

export type EngagementPosture = {
  state: string;
  label: string;
  display_label: string;
  description: string;
  tone: string;
  rank: number;
  derived: boolean;
  verified: boolean;
  evidence_count: number;
  evidence_ids: string[];
  reasons: EngagementPostureReason[];
  updated_at: string;
  method: string;
};

export type AuthStatus = {
  mode: string;
  state: 'open' | 'setup' | 'locked' | 'authenticated';
  authenticated: boolean;
  user: { user_id: string; display_name: string } | null;
  passkey_count: number;
  passkey_supported: boolean;
};

export type Agent = {
  agent_id: string;
  name: string;
  status: string;
  token_hint: string;
  role?: string;
  created_at: string;
  last_seen_at: string;
};

export type Member = {
  principal_id: string;
  principal_type: 'human' | 'agent';
  name: string;
  role: string;
  status?: string;
  last_seen_at?: string;
};

export type H3retikSession = {
  binding_id: string;
  engagement_id: string;
  session_id: string;
  label: string;
  lane?: string;
  status: string;
  actions_remaining?: number;
  seconds_left?: number;
  grace_seconds_left?: number;
  expires_at?: string;
  extendable?: boolean;
  created_at: string;
};

export type IdentitySnapshot = {
  members: Member[];
  agents: Agent[];
  h3retik_sessions: H3retikSession[];
  h3retik_workspace?: {
    configured: boolean;
    available: boolean;
    workspace_id?: string;
    job_count?: number;
    error?: string;
  };
};

export type Snapshot = {
  engagement: Engagement;
  posture: EngagementPosture;
  brief: {
    confirmed: Observation[];
    findings: Observation[];
    open_hypotheses: Hypothesis[];
    exhausted_paths: Attempt[];
    recent_attempts: Attempt[];
    pending_actions: Action[];
    regressions: Regression[];
    agent_instruction: string;
  };
  stats: { nodes: number; evidence: number; pending: number; loot: number; telemetry?: number; relationships?: number };
  nodes: GraphNode[];
  edges: GraphEdge[];
  events: MemoryEvent[];
  loot: LootArtifact[];
  primary_action: Action | null;
  memory: { online: boolean; last_event: string; event_count: number };
};

const fallbackEngagement: Engagement = {
  engagement_id: 'eng-preview-7af2',
  title: 'Operation Glasshouse',
  target: 'h1dr4.dev',
  mode: 'autonomous_lab',
  scope: 'Owned H1DR4 infrastructure',
  target_allowlist: ['h1dr4.dev'],
  allowed_lanes: ['web', 'local', 'osint'],
  rules: ['Human approval required before active execution'],
  operator_id: 'wexbt',
};

const confirmed: Observation[] = [
  { id: 'obs-1', statement: 'MCP endpoint reachable', source: 'curl headers', confidence: 1, kind: 'observation' },
  { id: 'obs-2', statement: 'H3RETIK gateway mapped', source: 'capability discovery', confidence: 1, kind: 'observation' },
  { id: 'obs-3', statement: 'HTTPS surface active', source: 'direct observation', confidence: .96, kind: 'observation' },
];

const hypotheses: Hypothesis[] = [
  { id: 'hyp-1', statement: 'Method-level rate limits differ', status: 'open' },
  { id: 'hyp-2', statement: 'Auth boundary exposes metadata', status: 'open' },
];

const exhausted: Attempt[] = [
  { id: 'try-1', approach: 'Legacy /api/v0 surface', outcome: 'Consistent 404', exhausted: true },
];

const action: Action = {
  id: 'act-09', target: 'h1dr4.dev', lane: 'web', command: 'curl -sSI https://h1dr4.dev',
  purpose: 'Compare security headers', risk: 'active', max_minutes: 5, budget_usdc: .19, status: 'human_required',
};

const regression: Regression = {
  id: 'reg-1', name: 'Security header baseline', check: 'curl -sSI https://h1dr4.dev', expected: 'Required headers remain present',
};

const loot: LootArtifact[] = [
  { id: 'loot-1', label: 'MCP capability manifest', type: 'SURFACE INTEL', source: 'h3retik:job-7af2', sensitive: false, sealed_preview: 'TELEMETRY SEALED', has_reveal: true, size_bytes: 1842, integrity: 'a81e5e0c74d9296f', recorded_at: '2026-08-31T15:01:39Z', job_id: 'job-7af2', preview_telemetry: { tools: 14, transport: 'streamable-http', endpoint: '/mcp' } },
  { id: 'loot-2', label: 'Authorization boundary telemetry', type: 'SECRET TELEMETRY', source: 'h3retik:job-7b01', sensitive: true, sealed_preview: '•••• •••• •••• ••••', has_reveal: true, size_bytes: 624, integrity: '58c02fa12b1019af', recorded_at: '2026-08-31T15:01:45Z', job_id: 'job-7b01', preview_telemetry: { credential_class: 'bearer', fingerprint: 'sha256:58c0…19af', exposure: 'metadata-only' } },
];

export const fallbackSnapshot: Snapshot = {
  engagement: fallbackEngagement,
  posture: {
    state: 'surface_mapped',
    label: 'SURFACE MAPPED',
    display_label: 'SURFACE MAPPED',
    description: 'The target surface is backed by verified telemetry.',
    tone: 'mapped',
    rank: 2,
    derived: true,
    verified: true,
    evidence_count: 2,
    evidence_ids: ['obs-1', 'obs-2'],
    reasons: [
      { record_id: 'obs-2', signal: 'surface_mapped', label: 'SURFACE MAPPED', summary: 'Mapped surface telemetry retained as sealed loot', source: 'capability discovery', actor_name: 'HERMES-03', recorded_at: '2026-08-31T15:01:39Z', rank: 2 },
      { record_id: 'obs-1', signal: 'recon_in_progress', label: 'RECON IN PROGRESS', summary: 'High-confidence telemetry recorded', source: 'curl headers', actor_name: 'RECON-01', recorded_at: '2026-08-31T15:01:31Z', rank: 1 },
    ],
    updated_at: '2026-08-31T15:01:39Z',
    method: 'sibyl-deterministic-evidence-v1',
  },
  brief: {
    confirmed,
    findings: [confirmed[0]],
    open_hypotheses: hypotheses,
    exhausted_paths: exhausted,
    recent_attempts: exhausted,
    pending_actions: [action],
    regressions: [regression],
    agent_instruction: 'Reason from confirmed evidence. Do not repeat the exhausted legacy API path without new evidence. Request policy evaluation before active testing.',
  },
  stats: { nodes: 7, evidence: 11, pending: 1, loot: loot.length },
  nodes: [
    { id: 'target', label: 'H1DR4.DEV', meta: 'PRIMARY TARGET', x: 49, y: 42, kind: 'target', detail: fallbackEngagement },
    { id: 'obs-1', label: 'MCP ENDPOINT', meta: 'CONFIRMED · 1.00', x: 73, y: 21, kind: 'confirmed', detail: confirmed[0] },
    { id: 'obs-2', label: 'H3RETIK', meta: 'CONFIRMED · 1.00', x: 79, y: 64, kind: 'confirmed', detail: confirmed[1] },
    { id: 'obs-3', label: 'HTTPS / 443', meta: 'CONFIRMED · 0.96', x: 24, y: 24, kind: 'confirmed', detail: confirmed[2] },
    { id: 'hyp-1', label: 'RATE LIMITS', meta: 'OPEN HYPOTHESIS', x: 25, y: 67, kind: 'hypothesis', detail: hypotheses[0] },
    { id: 'act-09', label: 'HEADER DIFF', meta: 'HUMAN REQUIRED', x: 78, y: 80, kind: 'action', detail: action },
    { id: 'reg-1', label: 'HEADER CHECK', meta: 'REGRESSION', x: 52, y: 84, kind: 'regression', detail: regression },
  ],
  edges: ['obs-1', 'obs-2', 'obs-3', 'hyp-1', 'act-09', 'reg-1'].map((to) => ({ from: 'target', to })),
  events: [
    { id: 'evt-1', time: '2026-08-31T15:01:47Z', type: 'fresh_process_recall', title: 'Fresh Process Recall', detail: 'Sibyl reconstructed engagement state' },
    { id: 'evt-2', time: '2026-08-31T15:01:45Z', type: 'attempt_recorded', title: 'Attempt Exhausted', detail: 'Legacy /api/v0 returned consistent 404' },
    { id: 'evt-3', time: '2026-08-31T15:01:39Z', type: 'observation_recorded', title: 'Capability Mapped', detail: 'H3RETIK session job lifecycle available' },
    { id: 'evt-4', time: '2026-08-31T15:01:31Z', type: 'hypothesis_recorded', title: 'Hypothesis Opened', detail: 'Inspect method-level authorization boundary' },
  ],
  loot,
  primary_action: action,
  memory: { online: false, last_event: '2026-08-31T15:01:47Z', event_count: 4 },
};
