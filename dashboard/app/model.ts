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

export type Observation = {
  id: string;
  statement: string;
  source: string;
  confidence: number;
  kind: string;
};

export type Hypothesis = { id: string; statement: string; status: string };
export type Attempt = { id: string; approach: string; outcome: string; exhausted: boolean };
export type Action = {
  id: string;
  target: string;
  lane: string;
  command: string;
  purpose: string;
  risk: string;
  max_minutes: number;
  budget_usdc: number;
  status: string;
};
export type Regression = { id: string; name: string; check: string; expected: string };

export type GraphNode = {
  id: string;
  label: string;
  meta: string;
  kind: string;
  x: number;
  y: number;
  detail: unknown;
};

export type GraphEdge = { from: string; to: string };
export type MemoryEvent = { id: string; time: string; type: string; title: string; detail: string };

export type Snapshot = {
  engagement: Engagement;
  brief: {
    confirmed: Observation[];
    open_hypotheses: Hypothesis[];
    exhausted_paths: Attempt[];
    recent_attempts: Attempt[];
    pending_actions: Action[];
    regressions: Regression[];
    agent_instruction: string;
  };
  stats: { nodes: number; evidence: number; pending: number };
  nodes: GraphNode[];
  edges: GraphEdge[];
  events: MemoryEvent[];
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

export const fallbackSnapshot: Snapshot = {
  engagement: fallbackEngagement,
  brief: {
    confirmed,
    open_hypotheses: hypotheses,
    exhausted_paths: exhausted,
    recent_attempts: exhausted,
    pending_actions: [action],
    regressions: [regression],
    agent_instruction: 'Reason from confirmed evidence. Do not repeat the exhausted legacy API path without new evidence. Request policy evaluation before active testing.',
  },
  stats: { nodes: 7, evidence: 11, pending: 1 },
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
  primary_action: action,
  memory: { online: false, last_event: '2026-08-31T15:01:47Z', event_count: 4 },
};
