// Types mirror api/server.py. The UI never computes a decision; it only renders what the engine returned.

export type Policy = { decision: "ALLOW" | "DENY"; policies: string[]; enforced?: boolean };

export type CellParams = Record<string, number | string | boolean>;
export type SimResult = {
  action_id: string;
  before: Record<string, CellParams>;
  after: Record<string, CellParams>;
  resolved: boolean;
  kpi_before: number;
  kpi_after: number;
};

// What the agent sent next to what the interceptor computed for Cedar (orchestrator/agent.py `checked`).
export type Checked = {
  claimed: Record<string, unknown>;
  listed_cells: number;
  server: { cell_count?: number; category?: string; score_ok?: boolean; licence_ok?: boolean };
  dropped: string[];
  notes: string[];
};

export type Step = {
  call: "apply_remediation" | "request_human_approval" | string;
  isError: boolean;
  text?: string | null;
  policy?: Policy | null;
  checked?: Checked | null;
  result?: (SimResult & { approval_id?: string }) | null;
  reason?: string;
};

export type Trace = {
  incident_id: string;
  category: string;
  pred: string;
  score: number;
  threshold: number;
  action: string;
  cells: string[];
  steps: Step[];
  outcome: "AUTO_APPLIED" | "HUMAN" | string;
  approval_id?: string;
};

export type Brief = { isError: boolean; text: string | null; policies: string[] | null; result: SimResult | null } | null;

export type Cal = {
  licensed: boolean;
  threshold: number | null;
  n: number;
  k: number;
  upper_bound: number | null;
  first_test?: { threshold: number; n: number; k: number; U: number } | null;
};

export type Heldout = {
  n_eligible: number;
  n_auto: number;
  autonomy_rate: number;
  errors: number;
  selective_error: number;
  ci90: [number, number] | null;
};

export type Risk = {
  alpha: number;
  delta: number;
  threshold: number;
  n: number;
  k: number;
  upper_bound: number;
  method: string;
  population: string;
};

export type Licence = {
  jti: string;
  status: "active" | "revoked" | string;
  exp: number;
  scope: { categories: string[]; actions: string[]; operators: string[] };
  risk: Risk;
};

export type AuditRow = {
  seq: number;
  ts: number;
  operator: string;
  kind: string;
  incident: string;
  detail: Record<string, unknown>;
};

export type MomentId = "earn" | "act" | "block" | "revoke" | "recertify" | "federation" | "warning" | "self_revoke";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Last = { name: MomentId; result: any } | null;

export type State = {
  data_source: string;
  licence: Licence | null;
  warned_categories: string[];
  approvals: { id: string; action: string; cells: number; reason: string }[];
  audit: AuditRow[];
  licence_events: AuditRow[];   // every licence issue and revocation, not only the tail
  last: Last;
};

export type LiveUnit = { run_id: string; passed: boolean; value: number; items: number };

export type LiveEvidence = {
  scope: "team" | "personal" | "rehearsal";
  team_code: string;
  when: string | null;
  policy_mode: string | null;
  signer: string | null;
  data_source: string | null;
  units: Partial<Record<"licence" | "allow" | "deny" | "adversarial" | "trace" | "pause", LiveUnit>>;
} | null;

export type LiveKind = "small" | "big" | "split" | "tampered";

export type LiveStatus = {
  enabled?: boolean;
  ready: boolean;
  reason?: string;
  account?: string;
  region?: string;
  policy_mode?: string | null;
  stack?: "running" | "paused";
  licence?: { jti: string; status: string } | null;
  checked_at?: string;
};

export type LiveHop = {
  rec_id: string;
  source: string;
  kind: string;
  ts: string | null;
  fields: Record<string, unknown>;
  cloudwatch?: string | null;
};

export type LiveCall = {
  trace_id: string;
  kind: LiveKind;
  incident: string;
  cells_sent: number;
  claimed_cells: number | null;
  setup_cells: number | null;
  decision: string;
  blocked_by: string;
  detail: string | null;
  token_ms: number;
  gateway_ms: number;
  sent_at: string;
  replied_at: string;
  gate: { decision: "PERMIT" | "FORBID" | "NOT_REACHED" | "UNKNOWN"; policy?: string | null; basis: string };
};

export type AlphaRow = {
  alpha: number;
  official: boolean;
  licensed: boolean;
  threshold: number | null;
  heldout_autonomy: number;
  heldout_error: number;
};

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`/api${path}`, { cache: "no-store", ...init });
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      msg = (await r.json()).detail ?? msg;
    } catch {}
    throw new Error(msg);
  }
  return r.json();
}

// The API refuses a live action without this header; a page on another site cannot send it.
const LIVE_POST: RequestInit = { method: "POST", headers: { "x-al-live": "1" } };

export const api = {
  state: () => call<State>("/state"),
  alphas: () => call<{ official_alpha: number; alphas: AlphaRow[] }>("/alphas"),
  evidence: () => call<{ live: LiveEvidence }>("/evidence"),
  run: (m: MomentId) => call<State>(`/moment/${m}`, { method: "POST" }),
  reset: () => call<State>("/reset", { method: "POST" }),
  policies: () => call<{ policies: Record<string, string> }>("/policies"),
  liveStatus: () => call<LiveStatus>("/live/status"),
  liveCall: (k: LiveKind) => call<LiveCall>(`/live/call/${k}`, LIVE_POST),
  liveTrace: (t: string) => call<{ trace_id: string; hops: LiveHop[] }>(`/live/trace/${t}`),
  liveResume: () => call<LiveStatus>("/live/stack/resume", LIVE_POST),
  livePause: () => call<LiveStatus>("/live/stack/pause", LIVE_POST),
  liveWithdraw: () => call<LiveStatus>("/live/licence/withdraw", LIVE_POST),
  liveNewLicence: () => call<LiveStatus>("/live/licence/new", LIVE_POST),
};

export const MOMENTS: { id: MomentId; n?: number; label: string; hint: string; needsLicence: boolean; tone?: string }[] = [
  { id: "earn", n: 1, label: "Earn", hint: "Calibrate on held-back incidents and issue a signed licence", needsLicence: false, tone: "signal" },
  { id: "act", n: 2, label: "Act", hint: "A confident diagnosis is fixed alone; a doubtful one goes to an engineer", needsLicence: true },
  { id: "block", n: 3, label: "Block", hint: "The agent asks to change 5 cells and claims 2; the hard rule refuses", needsLicence: true, tone: "ember" },
  { id: "revoke", n: 4, label: "Revoke", hint: "Withdraw the licence; the next action goes back to humans", needsLicence: true, tone: "ember" },
  { id: "recertify", label: "Re-certify", hint: "Run a new calibration round and issue a fresh licence", needsLicence: false },
  { id: "federation", n: 5, label: "Federate", hint: "Three operators pool masked error counts to earn one licence", needsLicence: false },
  { id: "warning", n: 6, label: "Warn", hint: "Operator B warns the others about a category; A stops acting on it", needsLicence: true, tone: "amber" },
  { id: "self_revoke", n: 7, label: "Self-revoke", hint: "Outcomes are watched after every action; drift makes the licence revoke itself", needsLicence: false, tone: "ember" },
];

export const pct = (x: number | null | undefined, d = 1) => (x == null ? "—" : `${(x * 100).toFixed(d)}%`);
