import type { ReactNode } from "react";

// Diagrams for the Help page, drawn as inline SVG in the console's own colours. Each one describes the system as
// built (README, aws/infra, demo/engine.py); none of them shows data. Colours keep the console's meaning:
// teal allowed or proven, amber a person decides, coral denied, grey plain infrastructure.

type Tone = "signal" | "amber" | "ember" | "seal" | "plain";
const STROKE: Record<Tone, string> = {
  signal: "var(--signal)", amber: "var(--amber)", ember: "var(--ember)", seal: "var(--seal-ui)", plain: "rgb(var(--line-rgb) / .5)",
};

function Box({ x, y, w, h, title, sub, tone = "plain" }: { x: number; y: number; w: number; h: number; title: string; sub?: string; tone?: Tone }) {
  const c = STROKE[tone];
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="12" fill="var(--figure)" stroke={c} strokeWidth={tone === "plain" ? 1 : 1.5} />
      <rect x={x} y={y} width={w} height={h} rx="12" fill={c} fillOpacity={tone === "plain" ? 0.03 : 0.08} />
      <text x={x + w / 2} y={sub ? y + h / 2 - 3 : y + h / 2 + 5} textAnchor="middle" fontSize="14.5" fontWeight="650" fill="var(--frost)">{title}</text>
      {sub && <text x={x + w / 2} y={y + h / 2 + 15} textAnchor="middle" fontSize="12" fill="var(--frost-2)">{sub}</text>}
    </g>
  );
}

function Arrow({ d, id, label, lx, ly, dashed, tone = "plain", anchor = "middle" }: {
  d: string; id: string; label?: string; lx?: number; ly?: number; dashed?: boolean; tone?: Tone; anchor?: "start" | "middle" | "end";
}) {
  const c = tone === "plain" ? "rgb(var(--line-rgb) / .65)" : STROKE[tone];
  return (
    <g>
      <path d={d} fill="none" stroke={c} strokeWidth="1.5" strokeDasharray={dashed ? "5 4" : undefined} markerEnd={`url(#${id}-${tone})`} />
      {label && <text x={lx} y={ly} textAnchor={anchor} fontSize="12" fill="var(--frost-2)">{label}</text>}
    </g>
  );
}

function Markers({ id }: { id: string }) {
  return (
    <defs>
      {(Object.keys(STROKE) as Tone[]).map((t) => (
        <marker key={t} id={`${id}-${t}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" fill={t === "plain" ? "rgb(var(--line-rgb) / .8)" : STROKE[t]} />
        </marker>
      ))}
    </defs>
  );
}

function Lane({ y, children }: { y: number; children: ReactNode }) {
  return <text x="12" y={y} fontSize="12.5" fontWeight="600" fill="var(--frost-3)">{children}</text>;
}

export function Figure({ title, caption, minWidth, children }: { title: string; caption: ReactNode; minWidth: number; children: ReactNode }) {
  return (
    <figure className="glass-card p-4 sm:p-5">
      <figcaption className="mb-3">
        <b className="block text-lg">{title}</b>
        <span className="muted mt-1 block text-body leading-relaxed">{caption}</span>
      </figcaption>
      <div className="overflow-x-auto">
        <div style={{ minWidth }}>{children}</div>
      </div>
    </figure>
  );
}

/** Everything that exists, on AWS and around it: proving once, enforcing on every call, people and shared state. */
export function ArchitectureDiagram() {
  const id = "arch";
  const row2 = [
    { t: "NetOps agent", s: "diagnoses, asks to act", tone: "plain" },
    { t: "Cognito", s: "token with its role", tone: "plain" },
    { t: "Gateway", s: "AgentCore, MCP", tone: "plain" },
    { t: "Interceptor", s: "server facts only", tone: "seal" },
    { t: "Cedar policy", s: "permit or forbid", tone: "seal" },
    { t: "Tool Lambda", s: "re-checks it all", tone: "seal" },
    { t: "Network", s: "simulated cells", tone: "signal" },
  ] as const;
  const X = (i: number) => 12 + i * 142;
  return (
    <svg viewBox="0 0 1000 486" role="img" aria-labelledby="arch-t" className="h-auto w-full">
      <title id="arch-t">System architecture: a proving pipeline that issues a signed licence, the enforcement path every tool call takes, and the people and shared state around it</title>
      <Markers id={id} />
      <Lane y={36}>Prove once, offline</Lane>
      {[
        ["TeleLogs test split", "818 single-cause faults"],
        ["SageMaker GPU", "classifier scores each"],
        ["Score cache, S3", "fingerprinted, trusted"],
        ["Calibration", "PREREG, fixed sequence"],
        ["AWS KMS", "signs the licence"],
      ].map(([t, s], i) => (
        <g key={t}>
          <Box x={12 + i * 198} y={48} w={174} h={64} title={t} sub={s} tone={i === 4 ? "signal" : "plain"} />
          {i < 4 && <Arrow id={id} d={`M${186 + i * 198},80 H${206 + i * 198}`} />}
        </g>
      ))}

      <Lane y={168}>Enforce, on every tool call</Lane>
      <Arrow id={id} tone="signal" d="M897,112 V146 H500 V226" label="signed licence, deployed with the Lambdas" lx={700} ly={140} />
      <Arrow id={id} tone="signal" d="M780,146 V226" />
      {row2.map((b, i) => (
        <g key={b.t}>
          <Box x={X(i)} y={230} w={124} h={64} title={b.t} sub={b.s} tone={b.tone} />
          {i < 6 && <Arrow id={id} d={`M${X(i) + 124},262 H${X(i + 1) - 4}`} />}
        </g>
      ))}

      <Box x={12} y={392} w={256} h={64} title="Engineer" sub="approves one exact change" tone="amber" />
      <Box x={367} y={392} w={266} h={64} title="Licences and warnings" sub="DynamoDB, read on every call" tone="plain" />
      <Box x={722} y={392} w={266} h={64} title="Risk monitor" sub="anytime-valid test on outcomes" tone="ember" />
      <Arrow id={id} tone="amber" d="M74,294 V388" label="not sure: ask" lx={82} ly={344} anchor="start" />
      <Arrow id={id} tone="amber" d="M210,388 V330 H358 V298" label="approved call (P3)" lx={230} ly={324} anchor="start" />
      <Arrow id={id} d="M500,392 V298" />
      <Arrow id={id} d="M600,392 V340 H760 V298" label="status, warnings" lx={612} ly={334} anchor="start" />
      <Arrow id={id} tone="ember" d="M840,298 V388" label="outcomes" lx={848} ly={344} anchor="start" />
      <Arrow id={id} tone="ember" d="M722,424 H637" label="revoke" lx={680} ly={416} />
    </svg>
  );
}

/** One tool call, as the policies decide it. */
export function DecisionDiagram() {
  const id = "dec";
  return (
    <svg viewBox="0 0 780 470" role="img" aria-labelledby="dec-t" className="mx-auto h-auto w-full max-w-[780px]">
      <title id="dec-t">How one tool call is decided: licence and score, then warnings, then the three-cell rule, which applies to engineers too</title>
      <Markers id={id} />
      <Box x={240} y={14} w={300} h={58} title="Agent diagnoses a fault" sub="the server looks up its score" />
      <Arrow id={id} d="M390,72 V96" />
      <Box x={240} y={100} w={300} h={58} title="Licence active, score ≥ λ̂?" sub="checked by the interceptor" tone="seal" />
      <Arrow id={id} d="M390,158 V182" label="yes" lx={398} ly={175} anchor="start" />
      <Box x={240} y={186} w={300} h={58} title="Category free of warnings?" sub="signed by other operators" tone="seal" />
      <Arrow id={id} d="M390,244 V268" label="yes" lx={398} ly={261} anchor="start" />
      <Box x={240} y={272} w={300} h={58} title="At most 3 cells?" sub="counted by the server, for everyone" tone="seal" />
      <Arrow id={id} tone="signal" d="M390,330 V368" label="yes" lx={398} ly={354} anchor="start" />
      <Box x={240} y={372} w={300} h={70} title="Change applied" sub="tool re-checks; outcome goes to the monitor" tone="signal" />

      <Box x={590} y={100} w={176} h={144} title="Engineer" sub="single use, 10 minutes" tone="amber" />
      <text x={678} y={200} textAnchor="middle" fontSize="12" fill="var(--frost-2)">exact incident, action, cells</text>
      <Arrow id={id} tone="amber" d="M540,129 H586" label="no" lx={562} ly={121} />
      <Arrow id={id} tone="amber" d="M540,215 H586" label="no" lx={562} ly={207} />
      <Arrow id={id} tone="amber" d="M678,244 V301 H544" label="checked too" lx={611} ly={293} />

      <Box x={14} y={272} w={180} h={58} title="Denied by F1" sub="no one can override it" tone="ember" />
      <Arrow id={id} tone="ember" d="M240,301 H198" label="no" lx={219} ly={293} />
    </svg>
  );
}

/** Federation: counts, not data, cross operator lines. */
export function FederationDiagram() {
  const id = "fed";
  const ops = [["Operator A", 22], ["Operator B", 112], ["Operator C", 202]] as const;
  return (
    <svg viewBox="0 0 900 306" role="img" aria-labelledby="fed-t" className="h-auto w-full">
      <title id="fed-t">Federation: each operator sends masked error counts, an aggregator adds them, and the pooled counts earn one federation-level licence</title>
      <Markers id={id} />
      {ops.map(([t, y]) => (
        <g key={t}>
          <Box x={14} y={y} w={210} h={62} title={t} sub="n and k at each threshold" />
          <Arrow id={id} d={`M224,${y + 31} C270,${y + 31} 270,145 312,145`} />
        </g>
      ))}
      <text x={268} y={60} fontSize="12" fill="var(--frost-2)">masked counts,</text>
      <text x={268} y={75} fontSize="12" fill="var(--frost-2)">never incidents</text>
      <Box x={316} y={112} w={230} h={66} title="Aggregator" sub="adds masks away; sees only sums" tone="seal" />
      <Arrow id={id} tone="signal" d="M546,145 H596" />
      <Box x={600} y={112} w={286} h={66} title="One federation licence" sub="same test, pooled evidence" tone="signal" />
      <text x={450} y={294} textAnchor="middle" fontSize="12" fill="var(--frost-2)">
        Separately, an operator that hits a hard rule signs a warning for that fault category; the others stop acting alone in it.
      </text>
    </svg>
  );
}

/** The licence's life: a sequence, so the steps are numbered. */
export const LIFECYCLE: { t: string; d: string; tone: Tone }[] = [
  { t: "Score", d: "A GPU classifier scores each held-back fault. Scores are fingerprinted so the agent can't supply its own.", tone: "plain" },
  { t: "Pre-register", d: "Thresholds, error budget and data hashes are fixed and hashed before any calibration result is seen.", tone: "plain" },
  { t: "Calibrate", d: "Thresholds are tested strict to loose. The loosest one whose error bound fits the 5% budget wins.", tone: "seal" },
  { t: "Sign", d: "AWS KMS signs a licence with the threshold, evidence, scope and an expiry.", tone: "signal" },
  { t: "Enforce", d: "Every tool call is checked against the licence, the live registry and the hard rules.", tone: "signal" },
  { t: "Watch", d: "Each autonomous outcome updates an anytime-valid test, checked after every action.", tone: "amber" },
  { t: "Revoke", d: "By a person, by the monitor, or by expiry. The next call is denied. Re-certifying issues a new licence.", tone: "ember" },
];

export function LifecycleFlow() {
  return (
    <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" aria-label="Licence lifecycle">
      {LIFECYCLE.map((s, i) => (
        <li key={s.t} className="glass-card relative p-4" style={{ borderColor: s.tone === "plain" ? undefined : `color-mix(in oklab, ${STROKE[s.tone]} 45%, transparent)` }}>
          <div className="flex items-center gap-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full text-sm font-bold"
              style={{ background: `color-mix(in oklab, ${STROKE[s.tone]} 18%, transparent)`, color: s.tone === "plain" ? "var(--frost)" : STROKE[s.tone] }}>
              {i + 1}
            </span>
            <b>{s.t}</b>
          </div>
          <p className="muted mt-2 text-body leading-relaxed">{s.d}</p>
        </li>
      ))}
      <li className="glass-card grid place-items-center p-4 text-center text-body muted">
        Back to step 1 for the next licence. A revoked licence is never switched back on.
      </li>
    </ol>
  );
}
