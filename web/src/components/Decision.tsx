"use client";

import { motion, useReducedMotion } from "motion/react";

import type { Brief, Cal, Checked, Heldout, Last, SimResult, Step, Trace } from "@/lib/api";
import { pct } from "@/lib/api";
import { EASE_OUT, ceremony, useCountUp } from "@/lib/ceremony";
import { splitStatement, usePolicies } from "@/lib/policies";
import { useSimple } from "@/lib/simple";

// ---------------------------------------------------------------- policy names in plain words
export function policyName(id: string): string {
  if (id === "F1") return "Hard rule: at most 3 cells";
  if (id === "F1m") return "Hard rule: cell count not checked";
  if (id === "F2") return "Hard rule: never autonomous";
  if (id.startsWith("F3")) return `Warned category ${id.slice(2)}`;
  if (id.startsWith("P2")) return `Licensed autonomy in ${id.slice(2)}`;
  if (id === "P3") return "Engineer-approved change";
  if (id === "P1") return "Read or ask for approval";
  return id;
}

// Simple view: the same facts in words a newcomer can follow.
export function plainPolicy(id: string | undefined): string {
  if (!id) return "the AI has no valid licence right now";
  if (id === "F1") return "no one may change more than 3 cell sites at once";
  if (id === "F1m") return "the system could not count the cell sites itself, so nothing may change";
  if (id === "F2") return "this kind of change always needs a person";
  if (id.startsWith("F3")) return "another operator warned about this type of fault";
  if (id.startsWith("P2")) return "the AI's licence covers this type of fault";
  if (id === "P3") return "a person approved this exact change";
  if (id === "P1") return "anyone may look and ask for approval";
  return id;
}

const OUTCOME: Record<string, { text: string; plain: string; tone: string }> = {
  AUTO_APPLIED: { text: "Fixed by the agent", plain: "AI fixed it alone", tone: "signal" },
  HUMAN: { text: "Handed to an engineer", plain: "Sent to a person", tone: "amber" },
};

// ---------------------------------------------------------------- enforcement path
type S = "pass" | "deny" | "human" | "skip" | "idle";
const NODES = [
  { k: "agent", label: "Agent", plain: "AI agent", icon: "M12 3a4 4 0 110 8 4 4 0 010-8zm-7 17a7 7 0 0114 0" },
  { k: "icpt", label: "Interceptor", plain: "Fact check", icon: "M4 7h16M4 12h10M4 17h6" },
  { k: "cedar", label: "Cedar policy", plain: "Rulebook", icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" },
  { k: "tool", label: "Tool re-check", plain: "Double-check", icon: "M5 12l4 4L19 6" },
  { k: "net", label: "Network", plain: "Network", icon: "M12 20v-6m-6 6a9 9 0 0112 0M3 10a13 13 0 0118 0" },
];

function pathStates(steps: Step[] | null): S[] {
  if (!steps) return ["idle", "idle", "idle", "idle", "idle"];
  const apply = steps.find((s) => s.call === "apply_remediation");
  if (!apply) return ["human", "skip", "skip", "skip", "skip"];
  if (!apply.isError) return ["pass", "pass", "pass", "pass", "pass"];
  if (apply.policy?.decision === "DENY") return ["pass", "pass", "deny", "skip", "skip"];
  return ["pass", "pass", "pass", "deny", "skip"];
}

// The node where the call stopped: the last one it reached.
const stopAt = (st: S[]) => st.reduce((a, s, i) => (s === "skip" ? a : i), 0);

// `steps` null: the path before any call has run, every check waiting.
export function PathRail({ steps }: { steps: Step[] | null }) {
  const simple = useSimple();
  const reduce = useReducedMotion();
  const st = pathStates(steps);
  const stop = stopAt(st);
  const t = stop * 0.15;   // in step with the nodes lighting up, 150 ms apart
  return (
    <ol className="relative grid grid-cols-5 items-start" aria-label="Enforcement path">
      {/* the call itself, travelling from the agent to the node that decided */}
      {!reduce && steps && stop > 0 && (
        <motion.span aria-hidden className="pointer-events-none absolute z-[1] h-3 w-3 rounded-full"
          style={{ top: 17, marginLeft: -6, background: st[stop] === "deny" ? "var(--ember)" : "var(--signal)",
            boxShadow: `0 0 14px 3px rgb(var(${st[stop] === "deny" ? "--ember-rgb" : "--signal-rgb"}) / .6)` }}
          initial={{ left: "10%", opacity: 0 }}
          animate={{ left: `${(stop + 0.5) * 20}%`, opacity: [0, 1, 1, 0] }}
          transition={{ left: { duration: t, ease: "linear" }, opacity: { duration: t + 0.35, times: [0, 0.08, 0.8, 1] } }} />
      )}
      {NODES.map((n, i) => (
        <li key={n.k} className="relative flex min-w-0 flex-col items-center text-center">
          {i > 0 && (
            <span
              aria-hidden
              className="absolute top-[23px] right-1/2 h-[2px] w-full"
              style={{
                background:
                  st[i] === "skip" || st[i] === "idle" ? "rgb(var(--fg-rgb) / .08)"
                  : st[i] === "deny" ? "linear-gradient(90deg, var(--signal), var(--ember))"
                  : "var(--signal)",
                opacity: st[i] === "skip" || st[i] === "idle" ? 1 : 0.55,
                zIndex: -1,
              }}
            />
          )}
          <span className="node rail-in" data-s={st[i]} style={{ animationDelay: `${i * 150}ms` }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d={st[i] === "deny" ? "M6 6l12 12M18 6L6 18" : n.icon} />
            </svg>
          </span>
          <span className={`mt-2 text-xs sm:text-sm ${st[i] === "skip" || st[i] === "idle" ? "faint" : "muted"}`}>{simple ? n.plain : n.label}</span>
        </li>
      ))}
    </ol>
  );
}

// ---------------------------------------------------------------- one incident, start to finish
// `brief`: on stage, show the path and verdict without the incident sentence (for moments with several traces).
export function TraceView({ t, title, brief }: { t: Trace | null | undefined; title: string; brief?: boolean }) {
  const simple = useSimple();
  if (!t) return null;
  const o = OUTCOME[t.outcome] ?? { text: t.outcome, plain: t.outcome, tone: "" };
  const apply = t.steps.find((s) => s.call === "apply_remediation");
  const ask = t.steps.find((s) => s.call === "request_human_approval");
  const passes = t.score >= t.threshold;
  const gap = claimGap(apply?.checked);
  return (
    <section className="glass-card reveal p-4 sm:p-5">
      <header className="flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="text-lg font-semibold tracking-tight">{title}</h3>
        <span className="pill" data-tone={o.tone}>{simple ? o.plain : o.text}</span>
      </header>
      {simple ? (
        <p className="muted mt-2 text-base leading-relaxed">
          The AI is <b style={{ color: passes ? "var(--signal)" : "var(--amber)" }}>{Math.floor(t.score * 100)}% sure</b> what
          caused this fault. It may act alone only when it is at least {Math.round(t.threshold * 100)}% sure.
        </p>
      ) : (
      <p className={`muted mt-2 text-body leading-relaxed ${brief ? "stage-hide" : ""}`}>
        Incident <b className="text-frost">{t.incident_id}</b> in category {t.category}. The model says cause{" "}
        <b className="text-frost">{t.pred}</b> with confidence{" "}
        <b style={{ color: passes ? "var(--signal)" : "var(--amber)" }}>{t.score.toFixed(3)}</b>, against a licensed
        threshold of {t.threshold.toFixed(2)}. Proposed fix: {t.action.replaceAll("_", " ")}.
      </p>
      )}
      <div className="mt-5"><PathRail steps={t.steps} /></div>
      {apply && simple && (
        <p className="mt-5 text-base leading-relaxed">
          {apply.isError ? (
            <><b style={{ color: "var(--ember)" }}>Stopped.</b> <span className="muted">Reason: {plainPolicy(apply.policy?.policies?.[0])}.
              {gap && ` The AI said it would change ${String(gap.claimed)} cell sites; the system counted ${gap.counted} itself.`}</span></>
          ) : (
            <><b style={{ color: "var(--signal)" }}>Allowed.</b> <span className="muted">Because {plainPolicy(apply.policy?.policies?.[0])}, the change was made on the simulated network.</span></>
          )}
        </p>
      )}
      {apply && !simple && (
        <div className="mt-5 flex flex-wrap items-center gap-2">
          {apply.isError ? (
            <>
              <span className="pill" data-tone="ember">Denied</span>
              {(apply.policy?.policies ?? []).length ? (
                apply.policy!.policies.map((p) => <span key={p} className="pill"><b>{p}</b> <span className="muted">{policyName(p)}</span></span>)
              ) : (
                <span className="pill">No permit matched, so the default is deny</span>
              )}
              <span className="faint text-sm">{apply.text}</span>
            </>
          ) : (
            <>
              <span className="pill" data-tone="signal">Allowed</span>
              {(apply.policy?.policies ?? []).map((p) => <span key={p} className="pill"><b>{p}</b> <span className="muted">{policyName(p)}</span></span>)}
            </>
          )}
        </div>
      )}
      {apply && !simple && <DecisionCard step={apply} stop={stopAt(pathStates(t.steps))} brief={brief} />}
      {ask && (
        <p className="stage-hide mt-3 text-sm" style={{ color: "var(--amber)" }}>
          {simple ? "A person has been asked to approve the fix." : `Approval request ${ask.result?.approval_id} queued for an engineer.`}
        </p>
      )}
      {apply && !apply.isError && apply.result && <CellDiff r={apply.result} />}
    </section>
  );
}

// ---------------------------------------------------------------- why the call stopped where it did
// The facts Cedar decided on, as the interceptor computed them, next to what the agent claimed; then the policy
// that fired, quoted from the deployed text with those values set beside the fields they fill. Nothing here is
// computed by the UI: values come from the gateway's response, text from the API.
const SERVER_FIELD = /(context\.input\.(?:cell_count|category|score_ok|licence_ok))\b/;

function claimGap(c: Checked | null | undefined): { claimed: unknown; counted: number } | null {
  if (!c || c.claimed.cell_count === undefined || c.server.cell_count === undefined) return null;
  return c.claimed.cell_count === c.server.cell_count ? null : { claimed: c.claimed.cell_count, counted: c.server.cell_count };
}

// A long condition is cut to the lines that test interceptor-computed fields, with … where lines were left out;
// the full text stays one click away under "Full statement".
function focus(condition: string): string {
  const lines = condition.split("\n");
  if (lines.length <= 3) return condition;
  const out: string[] = [];
  lines.forEach((l, i) => {
    const keep = i === 0 || i === lines.length - 1 || SERVER_FIELD.test(l);
    if (keep) out.push(i === 0 || i === lines.length - 1 ? l : "  " + l.trim());
    else if (out[out.length - 1] !== "  …") out.push("  …");
  });
  return out.join("\n");
}

const yes = (v: boolean | undefined) => (v === undefined ? "—" : v ? "yes" : "no");

function DecisionCard({ step, stop, brief }: { step: Step; stop: number; brief?: boolean }) {
  const reduce = useReducedMotion();
  const policies = usePolicies();
  const c = step.checked;
  const fired = step.policy?.policies ?? [];
  // A default deny names no policy, and a forbid can hide a second reason (a revoked licence on a 5-cell call):
  // in either case also quote the permit that would have allowed the call, so its failed condition shows.
  const permit = c?.server.category ? `P2${c.server.category}` : null;
  const permitFailed = c?.server.licence_ok === false || c?.server.score_ok === false;
  const shown = [...fired, ...(permit && (!fired.length || permitFailed) ? [permit] : [])];
  const toolRefused = step.isError && step.policy?.decision === "ALLOW";
  const gap = claimGap(c);
  return (
    <motion.div className={`relative mt-5 rounded-2xl border border-fg/10 bg-sink p-4 sm:p-5 ${brief || !step.isError ? "stage-hide" : ""}`}
      initial={reduce ? false : { opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay: stop * 0.15 + 0.25, duration: 0.4, ease: EASE_OUT }}>
      <span aria-hidden className="absolute -top-[7px] h-3 w-3 rotate-45 border-l border-t border-fg/10 bg-sink"
        style={{ left: `calc(${(stop + 0.5) * 20}% - 6px)` }} />
      <div className="space-y-4">
        {c && (
          <div>
            <p className="stage-hide faint mb-2 text-xs">What Cedar decided on, computed by the interceptor. Nothing the agent sends about itself is used.</p>
            <dl className="grid grid-cols-2 gap-x-5 gap-y-2.5 text-sm sm:grid-cols-4">
              <div>
                <dt className="faint">Cells counted</dt>
                <dd><b className="text-lg">{c.server.cell_count ?? "—"}</b>
                  {gap && <span className="ml-2" style={{ color: "var(--ember)" }}>agent claimed <s>{String(gap.claimed)}</s></span>}</dd>
              </div>
              <div><dt className="faint">Category</dt><dd className="font-semibold">{c.server.category ?? "—"}</dd></div>
              <div><dt className="faint">Confident enough</dt><dd className="font-semibold">{yes(c.server.score_ok)}</dd></div>
              <div><dt className="faint">Licence re-verified</dt><dd className="font-semibold">{yes(c.server.licence_ok)}</dd></div>
            </dl>
            {c.dropped.length > 0 && (
              <p className="stage-hide faint mt-2 text-xs">Dropped from the agent&rsquo;s request: <b className="text-frost">{c.dropped.join(", ")}</b></p>
            )}
            {c.notes.map((n) => <p key={n} className="stage-hide faint mt-1 text-xs leading-relaxed">{n}</p>)}
          </div>
        )}
        <div className="min-w-0 space-y-3">
          {toolRefused && <p className="text-sm">Cedar allowed the call; the tool&rsquo;s own re-check refused it: <span className="muted">{step.text}</span></p>}
          {shown.map((id) => <PolicyQuote key={id} id={id} fired={fired.includes(id)} text={policies?.[id]} server={c?.server} />)}
          {!shown.length && <p className="muted text-sm">No permit matched, so the default is deny.</p>}
        </div>
      </div>
    </motion.div>
  );
}

function PolicyQuote({ id, fired, text, server }: {
  id: string; fired: boolean; text: string | undefined; server: Checked["server"] | undefined;
}) {
  const s = text ? splitStatement(text) : null;
  const forbid = s ? s.effect === "forbid" : id.startsWith("F");
  return (
    <div className={fired ? undefined : "stage-hide"}>
      <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
        <b style={{ color: fired ? (forbid ? "var(--ember)" : "var(--signal)") : undefined }}>Cedar {id}</b>
        <span className="faint text-xs">{fired ? (forbid ? "fired. A forbid overrides every permit." : "matched.") : "did not match, so the default is deny."}</span>
      </div>
      {s ? (
        <>
          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-xl border border-fg/10 px-3.5 py-3 font-[family-name:var(--font-serial)] text-caption leading-relaxed">
            <code>
              <span className="faint">{s.effect}(…) </span>
              {focus(s.condition).split(SERVER_FIELD).map((part, i) => {
                if (i % 2 === 0) return <span key={i}>{part}</span>;
                const field = part.split(".").pop() as keyof Checked["server"];
                const v = server?.[field];
                return (
                  <span key={i}>
                    <b>{part}</b>
                    {v !== undefined && (
                      <span className="mx-1 rounded-md px-1.5 py-px font-semibold"
                        style={v === false
                          ? { background: "rgb(var(--ember-rgb) / .14)", color: "var(--ember)" }
                          : { background: "rgb(var(--signal-rgb) / .14)", color: "var(--signal)" }}
                        title="The value the interceptor computed">{String(v)}</span>
                    )}
                  </span>
                );
              })}
            </code>
          </pre>
          <details className="disclosure stage-hide mt-1.5 text-xs">
            <summary className="faint py-2.5 sm:py-0">Full statement, as deployed</summary>
            <pre className="mt-1.5 overflow-x-auto rounded-xl border border-fg/10 px-3.5 py-3 font-[family-name:var(--font-serial)] text-xs leading-relaxed">{text}</pre>
          </details>
        </>
      ) : (
        <p className="faint mt-1 text-xs">Policy text not loaded.</p>
      )}
    </div>
  );
}

const PARAMS: Record<string, string> = {
  downtilt_deg: "Downtilt (°)", pci: "PCI", ho_ttt_ms: "Handover TTT (ms)", ho_a3_offset_db: "A3 offset (dB)",
};

export function CellDiff({ r }: { r: SimResult }) {
  const simple = useSimple();
  const rows = Object.keys(r.before).sort().flatMap((c) =>
    Object.keys(PARAMS).filter((k) => r.before[c][k] !== r.after[c][k]).map((k) => ({ c, k, a: r.before[c][k], b: r.after[c][k] })),
  );
  const max = Math.max(r.kpi_before, r.kpi_after, 1);
  return (
    <div className={`stage-hide mt-5 grid gap-4 ${simple ? "" : "sm:grid-cols-2"}`}>
      <div hidden={simple}>
        <div className="faint mb-2 text-sm">What changed on the simulated cells</div>
        {!rows.length && <p className="muted text-sm">This action records the diagnosis and closes the incident; no cell parameters change.</p>}
        <ul className="space-y-1.5">
          {rows.map((x) => (
            <li key={x.c + x.k} className="flex items-center justify-between rounded-2xl bg-fg/[.04] px-3 py-2 text-sm">
              <span><b>{x.c}</b> <span className="muted">{PARAMS[x.k]}</span></span>
              <span><span className="faint">{String(x.a)}</span> <span className="muted">to</span> <b style={{ color: "var(--signal)" }}>{String(x.b)}</b></span>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <div className="faint mb-2 text-sm">{simple ? "Network speed for users, Mbps (simulated)" : "Throughput, Mbps"}</div>
        {[["Before", r.kpi_before, "rgb(var(--fg-rgb) / .35)"], ["After", r.kpi_after, "var(--signal)"]].map(([l, v, c]) => (
          <div key={l as string} className="mb-2">
            <div className="flex justify-between text-sm"><span className="muted">{l}</span><b>{v as number}</b></div>
            <div className="mt-1 h-2.5 overflow-hidden rounded-full bg-fg/[.06]">
              <div className="h-full rounded-full" style={{ width: `${((v as number) / max) * 100}%`, background: c as string, transition: "width 900ms" }} />
            </div>
          </div>
        ))}
        <p className="faint mt-2 text-xs leading-relaxed">
          Simulated network. Whether it is resolved is decided from the ground-truth label, so this shows enforcement,
          not remediation quality.
        </p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- calibration
type TraceRow = [number, number, number, number, boolean];

// Plays the test as it ran: the budget line first, then each threshold strict to loose with the line drawn point to
// point, then the licensed threshold. Timings come from the shared ceremony so the licence fills in alongside.
export function CalibrationChart({ trace, alpha }: { trace: TraceRow[]; alpha: number }) {
  const reduce = useReducedMotion();
  const T = ceremony(trace.length);
  const W = 640, H = 220, P = 40;
  const yMax = Math.max(alpha * 1.6, ...trace.map((r) => Math.min(r[3], alpha * 2)));
  const x = (i: number) => P + (i * (W - 2 * P)) / Math.max(trace.length - 1, 1);
  const y = (u: number) => H - P - (Math.min(u, yMax) / yMax) * (H - 2 * P);
  const last = trace.reduce((acc, r, i) => (r[4] ? i : acc), -1);   // licensed threshold = last pass in the sequence
  const at = (delay: number, duration = 0.4) => ({ delay, duration, ease: EASE_OUT });
  const play = <V,>(from: V, to: V) => (reduce ? { initial: false as const, animate: to } : { initial: from, animate: to });
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img"
      aria-label="Upper bound U at each threshold tested, against the alpha budget">
      <motion.line x1={P} x2={W - P} y1={y(alpha)} y2={y(alpha)} stroke="var(--amber)" strokeDasharray="5 6" strokeOpacity={0.8}
        {...play({ pathLength: 0 }, { pathLength: 1 })} transition={at(0, 0.45)} />
      <motion.text x={W - P} y={y(alpha) - 8} textAnchor="end" fill="var(--amber)" fontSize="12"
        {...play({ opacity: 0 }, { opacity: 1 })} transition={at(0.25)}>α = {pct(alpha, 0)}</motion.text>
      {trace.slice(1).map((r, i) => (
        <motion.line key={`s${i}`} x1={x(i)} y1={y(trace[i][3])} x2={x(i + 1)} y2={y(r[3])} stroke="rgb(var(--fg-rgb) / .35)" strokeWidth={1.5}
          {...play({ pathLength: 0 }, { pathLength: 1 })} transition={at(T.firstPoint + i * T.step + T.step * 0.35, T.step * 0.65)} />
      ))}
      {trace.map((r, i) => (
        <motion.circle key={i} cx={x(i)} cy={y(r[3])} r={r[4] ? 3.5 : 5} fill={r[4] ? "var(--signal)" : "var(--ember)"}
          {...play({ scale: 0, opacity: 0 }, { scale: 1, opacity: 1 })}
          transition={{ delay: T.firstPoint + i * T.step, type: "spring", stiffness: 520, damping: 22 }}>
          <title>{`λ ${r[0]} · accepted ${r[1]} · errors ${r[2]} · U ${pct(r[3], 2)}`}</title>
        </motion.circle>
      ))}
      <text x={P - 8} y={y(0) + 4} textAnchor="end" fill="var(--frost-3)" fontSize="12">0%</text>
      <text x={P - 8} y={y(yMax) + 4} textAnchor="end" fill="var(--frost-3)" fontSize="12">{pct(yMax, 0)}</text>
      <line x1={P} x2={W - P} y1={y(0)} y2={y(0)} stroke="rgb(var(--fg-rgb) / .1)" />
      {last >= 0 && (
        <motion.g {...play({ opacity: 0, y: -10 }, { opacity: 1, y: 0 })} transition={at(T.decided, 0.5)}>
          <line x1={x(last)} x2={x(last)} y1={y(trace[last][3]) + 8} y2={y(0)} stroke="var(--signal)" strokeOpacity={0.5} strokeDasharray="3 4" />
          <text x={x(last) + (last > trace.length / 2 ? -6 : 6)} y={y(trace[last][3]) + 22} textAnchor={last > trace.length / 2 ? "end" : "start"}
            fill="var(--signal)" fontSize="12" fontWeight="600">λ̂ {trace[last][0]}</text>
        </motion.g>
      )}
      <text x={P} y={H - 8} fill="var(--frost-3)" fontSize="12">λ {trace[0]?.[0]}</text>
      <text x={W - P} y={H - 8} textAnchor="end" fill="var(--frost-3)" fontSize="12">λ {trace.at(-1)?.[0]}</text>
    </svg>
  );
}

// A stat that lands when its value is decided and counts up to it. Only quantities that really accumulate count
// (cases, rates); a decided value (the threshold) lands without counting. `fmt` turns the running value into text.
function CountStat({ to, fmt, l, tone, delay }: { to: number; fmt: (v: number) => string; l: string; tone?: string; delay: number }) {
  const reduce = useReducedMotion();
  const v = useCountUp(to, delay);
  return (
    <motion.div className="glass-card px-4 py-3" initial={reduce ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.45, ease: EASE_OUT }}>
      <div className="text-2xl font-semibold tracking-tight tabular-nums" style={{ color: tone }}>{fmt(v)}</div>
      <div className="muted text-sm">{l}</div>
    </motion.div>
  );
}

function Stat({ v, l, tone }: { v: string; l: string; tone?: string }) {
  return (
    <div className="glass-card px-4 py-3">
      <div className="text-2xl font-semibold tracking-tight" style={{ color: tone }}>{v}</div>
      <div className="muted text-sm">{l}</div>
    </div>
  );
}

// ---------------------------------------------------------------- per-moment stage
const TITLES: Record<string, [string, string]> = {
  earn: ["The licence was earned", "Thresholds are tested from strict to loose, in a fixed order. Testing stops at the first one whose error bound goes over budget."],
  act: ["Confidence decides who acts", "Above the licensed threshold the agent fixes the fault itself. Below it, an engineer approves the exact change."],
  block: ["A hard rule held", "The agent asked to change 5 cells and claimed 2. The interceptor counts the real cells, and Cedar refuses, even for an engineer."],
  revoke: ["Control went back to humans", "The licence was withdrawn. The very next confident diagnosis is no longer allowed to act alone."],
  recertify: ["A new licence was issued", "A fresh calibration round produced a new licence. A revoked licence is never switched back on."],
  federation: ["Three operators, one licence", "Each operator alone has too little evidence. Masked sums of their error counts are enough together."],
  warning: ["A warning crossed operators", "Operator B hit a hard rule and sent a signed warning. Operator A stops acting alone in that category only."],
  self_revoke: ["The licence revoked itself", "Every autonomous outcome updates an anytime-valid test. On the proven licence's real record it stays quiet. A fresh licence then meets injected drift from its first action, and the test crosses its bar and withdraws it, no human needed."],
};

const SELF_REVOKE_HELD = ["The licence held",
  "Every autonomous outcome updates an anytime-valid test. A long in-distribution record is strong evidence the licence is sound, so this much injected drift did not cross the bar."];

const PLAIN_TITLES: Record<string, string> = {
  earn: "The AI was tested before it may act alone",
  act: "Sure, the AI acts. Unsure, a person decides.",
  block: "A hard limit stopped the AI",
  revoke: "The licence was taken away",
  recertify: "The AI earned a new licence",
  federation: "Three operators, one shared licence",
  self_revoke: "The AI lost its licence on its own record",
  warning: "One operator\u2019s warning protected another",
};

// One paragraph per moment, built from the engine's own numbers.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function plainSummary(name: string, r: any): string {
  const sure = (t?: Trace | null) => (t ? `${Math.floor(t.score * 100)}%` : "very");
  switch (name) {
    case "earn": {
      const c = r.calibration;
      return c.licensed
        ? `The AI was tested on ${c.n} past faults it would have handled alone, and it was wrong on ${c.k} of them. Even allowing for bad luck, its rate of wrong diagnoses is at most ${pct(c.upper_bound, 2)}, inside the ${pct(c.alpha, 0)} limit agreed in advance. So it gets a signed licence to fix faults alone, and that licence has an expiry time.`
        : `The AI could not show that its rate of wrong diagnoses stays inside the ${pct(c.alpha, 0)} limit, so it gets no licence and people stay in charge.`;
    }
    case "act":
      return `When the AI was ${sure(r.auto)} sure of the cause, it fixed the fault itself on the simulated network. When it was only ${sure(r.human)} sure, it asked a person, ${r.engineer_execution && !r.engineer_execution.isError ? "who approved the change" : "who now decides"}. How sure the AI must be was set by the test, not by the AI.`;
    case "block":
      return `The AI tried to change 5 cell sites at once and claimed it was only 2. The system counts the real number itself, and the rule says no one changes more than 3 at once. The AI was stopped, and so was an engineer who tried the same change. ${r.state_changes === 0 ? "Nothing on the network changed." : `${r.state_changes} changes were made.`}`;
    case "revoke":
      return `We took the AI\u2019s licence away. On the very next fault the AI was ${sure(r.next_call)} sure, but it was no longer allowed to fix it alone, so it went to a person instead. One action hands control back to people.`;
    case "recertify":
      return "The AI passed a fresh test and received a new licence. The withdrawn licence can never be switched back on.";
    case "federation": {
      const alone = Object.values(r.alone as Record<string, Cal>).filter((c) => c.licensed).length;
      return `Each operator on its own had limited evidence: ${alone} of 3 could license the AI alone. By adding up only their counts of right and wrong answers, without showing each other any data, together they ${r.pooled.licensed ? "earned one shared licence" : "still could not earn a licence"}. The shared licence speaks for the group, not for each operator separately.`;
    }
    case "warning":
      return `Operator B\u2019s AI tried to break a hard limit on one type of fault, so B sent the other operators a signed warning. Operator A\u2019s AI now ${r.A_same_category?.outcome === "HUMAN" ? "asks a person" : "still acts alone"} for that type of fault, and ${r.A_other_category?.outcome === "AUTO_APPLIED" ? "still fixes other types alone" : "also asks a person for other types"}.`;
    case "self_revoke": {
      const a = r.in_distribution, b = r.synthetic_drift;
      return `After the licence was issued, every fault the AI fixed alone was checked against what was really wrong. On ${a.outcomes} normal faults it was wrong ${a.errors} times, and the licence stayed. Then a new licence was issued, and from its first fault we made the AI's confidence read too high, a made-up test of drift. ${b.revoked_after ? `After ${b.revoked_after} faults, with ${b.errors} wrong, the evidence was strong enough and the new licence withdrew itself.` : "The evidence never got strong enough to withdraw the new licence."} ${b.revoked_after ? "The next fault went to a person. " : ""}If the AI really stays inside its limit, this check wrongly withdraws a licence at most ${pct(r.delta, 0)} of the time, however often it is checked.`;
    }
  }
  return "";
}

// `run` counts presses, so every result replays its entrance, even one identical to the last.
export default function Decision({ last, alpha, run }: { last: Last; alpha: number; run: number }) {
  const simple = useSimple();
  if (!last) {
    return (
      <div className="grid min-h-[340px] place-items-center p-5 text-center sm:p-7">
        <div className="w-full max-w-xl">
          <h2 className="text-2xl font-semibold tracking-tight">Nothing has happened yet</h2>
          <p className="muted mt-2 leading-relaxed">
            {simple ? (
              <>Press <b className="text-frost">Earn</b> to start. The AI is tested first, and only if it passes does it get permission to fix faults on its own.</>
            ) : (
              <>Start with <b className="text-frost">Earn</b>. The agent proves its error rate on held-back incidents and gets a
              signed licence, then you can watch every action pass through policy.</>
            )}
          </p>
          <div className="mt-8 opacity-80"><PathRail steps={null} /></div>
          <p className="faint mt-3 text-caption">{simple ? "Every action the AI tries goes through these checks, in this order." : "Every tool call the agent makes travels this path."}</p>
        </div>
      </div>
    );
  }
  const r = last.result;
  // Self-revoke reports what the test did; on real data the drift may not be enough to withdraw the licence.
  const held = last.name === "self_revoke" && r.status !== "revoked";
  const [title, sub] = held ? SELF_REVOKE_HELD : TITLES[last.name] ?? [last.name, ""];
  if (simple) {
    return (
      <div key={`${run}-${last.name}`} className="reveal space-y-5 p-5 sm:p-7">
        <h2 className="text-3xl font-semibold leading-tight tracking-[-0.02em]">{held ? "The AI kept its licence: the test saw no proof of a problem" : PLAIN_TITLES[last.name] ?? title}</h2>
        <p className="glass-card max-w-[72ch] p-4 text-lg sm:p-5 leading-[1.7]">{plainSummary(last.name, r)}</p>
        {last.name === "earn" && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Stat v={`${r.calibration.k} of ${r.calibration.n}`} l="wrong in the test" />
            <Stat v={`at most ${pct(r.calibration.upper_bound, 2)}`} l={`worst-case wrong rate, limit ${pct(r.calibration.alpha, 0)}`} tone="var(--signal)" />
            <Stat v={pct(r.heldout.autonomy_rate, 0)} l="of new faults it could fix alone" />
          </div>
        )}
        {last.name === "act" && (<><TraceView t={r.auto} title="The AI was sure" /><TraceView t={r.human} title="The AI was unsure" /></>)}
        {last.name === "block" && (
          <>
            <div className="grid grid-cols-2 gap-3 sm:max-w-md">
              <Stat v={String(r.state_changes)} l="changes made to the network" tone={r.state_changes === 0 ? "var(--signal)" : "var(--ember)"} />
              <Stat v="3" l="most cell sites anyone may change at once" />
            </div>
            <TraceView t={r.agent} title="What the AI tried" />
          </>
        )}
        {last.name === "revoke" && <TraceView t={r.next_call} title="The next fault" />}
        {last.name === "warning" && (<><TraceView t={r.A_same_category} title="Operator A, the warned type of fault" /><TraceView t={r.A_other_category} title="Operator A, another type of fault" /></>)}
        {last.name === "federation" && <FederationView r={r} />}
        {last.name === "self_revoke" && <TraceView t={r.next_call} title="The next fault" />}
      </div>
    );
  }
  return (
    <div key={`${run}-${last.name}`} className="reveal space-y-5 p-5 sm:p-7">
      <header>
        <h2 className="text-3xl font-semibold leading-tight tracking-[-0.02em]">{title}</h2>
        <p className="muted mt-1.5 max-w-[68ch] leading-relaxed">{sub}</p>
      </header>

      {last.name === "earn" && <EarnView r={r} alpha={alpha} />}
      {last.name === "act" && (
        <>
          <div className="trace-pair grid gap-5">
            <TraceView t={r.auto} title="Confident diagnosis" />
            <TraceView t={r.human} title="Doubtful diagnosis" />
          </div>
          {r.engineer_execution && <EngineerLine b={r.engineer_execution} />}
        </>
      )}
      {last.name === "block" && (
        <>
          <TraceView t={r.agent} title="Agent requests 5 cells, claims 2" />
          {r.engineer_with_approval && <EngineerLine b={r.engineer_with_approval} />}
          <div className="grid grid-cols-2 gap-3 sm:max-w-md">
            <Stat v={String(r.state_changes)} l="network changes made" tone={r.state_changes === 0 ? "var(--signal)" : "var(--ember)"} />
            <Stat v="3" l="cell limit, for everyone" />
          </div>
        </>
      )}
      {last.name === "revoke" && (
        <>
          <p className="pill" data-tone="ember">Licence {String(r.revoked_jti).slice(0, 8)} revoked</p>
          <TraceView t={r.next_call} title="The next confident diagnosis" />
        </>
      )}
      {last.name === "recertify" && <p className="pill" data-tone="signal">New licence {String(r.licence).slice(0, 8)}</p>}
      {last.name === "federation" && <FederationView r={r} />}
      {last.name === "self_revoke" && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:max-w-xl sm:grid-cols-4">
            <Stat v={`${r.in_distribution.errors}/${r.in_distribution.outcomes}`} l="wrong, in distribution" />
            <Stat v={String(r.in_distribution.peak_e)} l={`peak evidence (bar ${r.revoke_at_e})`} tone="var(--signal)" />
            <Stat v={`${r.synthetic_drift.errors}/${r.synthetic_drift.outcomes}`} l={`wrong, synthetic drift +${r.synthetic_drift.score_offset}`} tone="var(--ember)" />
            <Stat v={r.synthetic_drift.revoked_after ? String(r.synthetic_drift.revoked_after) : "—"} l="drift outcomes to revoke" tone="var(--ember)" />
          </div>
          <div className="flex flex-wrap gap-2">
            {r.in_distribution.jti && (
              <p className="pill" data-tone={r.in_distribution.status === "revoked" ? "ember" : "signal"}>Proven licence {String(r.in_distribution.jti).slice(0, 8)} {r.in_distribution.status}</p>
            )}
            <p className="pill" data-tone={r.status === "revoked" ? "ember" : "signal"}>Fresh licence {String(r.jti).slice(0, 8)} {r.status}</p>
          </div>
          <TraceView t={r.next_call} title="The next confident diagnosis" />
        </>
      )}
      {last.name === "warning" && (
        <>
          <TraceView t={r.B_attempt} title="Operator B oversteps" brief />
          <p className="pill" data-tone="amber">
            {r.warning.already_active
              ? <>Signed warning from {r.warning.issuer} on category {r.warning.category} is still in force; one per category at a time</>
              : <>Signed warning from {r.warning.issuer}: category {r.warning.category}, reviewer confirmed</>}
          </p>
          <div className="trace-pair grid gap-5">
            <TraceView t={r.A_same_category} title="Operator A, same category" brief />
            <TraceView t={r.A_other_category} title="Operator A, another category" brief />
          </div>
        </>
      )}
    </div>
  );
}

function EngineerLine({ b }: { b: NonNullable<Brief> }) {
  return (
    <div className="stage-hide glass-card reveal flex flex-wrap items-center gap-2 px-5 py-4">
      <span className="font-semibold">Engineer approves and executes</span>
      {b.isError ? (
        <>
          <span className="pill" data-tone="ember">Denied</span>
          {(b.policies ?? []).map((p) => <span key={p} className="pill"><b>{p}</b> <span className="muted">{policyName(p)}</span></span>)}
        </>
      ) : (
        <>
          <span className="pill" data-tone="signal">Allowed</span>
          {(b.policies ?? []).map((p) => <span key={p} className="pill"><b>{p}</b> <span className="muted">{policyName(p)}</span></span>)}
        </>
      )}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function EarnView({ r, alpha }: { r: any; alpha: number }) {
  const c = r.calibration;
  const h: Heldout = r.heldout;
  const T = ceremony(c.trace.length);
  const reduce = useReducedMotion();
  return (
    <>
      <div className="glass-card p-4 sm:p-5">
        <CalibrationChart trace={c.trace} alpha={alpha} />
      </div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <CountStat to={0} fmt={() => (c.threshold == null ? "—" : `≥ ${c.threshold.toFixed(2)}`)} l="licensed threshold λ̂" tone="var(--signal)" delay={T.decided} />
        <CountStat to={c.n} fmt={(v) => `${Math.round(v)} / ${c.k}`} l="accepted / wrong" delay={T.decided + 0.08} />
        <CountStat to={c.upper_bound} fmt={(v) => pct(v, 2)} l={`bound U, budget ${pct(c.alpha, 0)}`} delay={T.decided + 0.16} />
        <CountStat to={h.autonomy_rate} fmt={(v) => pct(v)} l="held-out handled alone" delay={T.decided + 0.24} />
      </div>
      <motion.p className="faint text-sm leading-relaxed" initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }}
        transition={{ delay: T.decided + 0.6, duration: 0.5 }}>
        Held-out check: {h.errors} wrong out of {h.n_auto} autonomous diagnoses ({pct(h.selective_error, 2)}), 90% interval{" "}
        {h.ci90 ? `${pct(h.ci90[0], 2)} to ${pct(h.ci90[1], 2)}` : "—"}. Confidence δ = {c.delta}. Pre-registered as{" "}
        {String(c.prereg).slice(0, 19)}. The bound covers wrong autonomous diagnoses, not action safety.
      </motion.p>
    </>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function FederationView({ r }: { r: any }) {
  const simple = useSimple();
  const alone = r.alone as Record<string, Cal>;
  const per = r.per_operator_heldout as Record<string, Heldout>;
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-3">
        {Object.entries(alone).map(([op, c]) => (
          <div key={op} className="glass-card p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <b className="whitespace-nowrap text-lg">Operator {op}</b>
              <span className="pill" data-tone={c.licensed ? "signal" : "ember"}>{c.licensed ? (simple ? "Enough evidence alone" : "Licensed alone") : (simple ? "Too little evidence alone" : "Not enough alone")}</span>
            </div>
            <p className="muted mt-2 text-sm" hidden={simple}>
              First test: {c.first_test?.n} accepted, {c.first_test?.k} wrong, U {pct(c.first_test?.U, 1)}
            </p>
            {per[op] && !simple && (
              <p className="faint mt-1 text-sm">
                Held-out with pooled licence: {pct(per[op].autonomy_rate)} alone, {per[op].errors}/{per[op].n_auto} wrong
              </p>
            )}
          </div>
        ))}
      </div>
      <div className="glass-card flex flex-wrap items-center gap-3 p-4">
        <span className="pill" data-tone={r.pooled.licensed ? "signal" : "ember"}>
          {simple ? (r.pooled.licensed ? "Together: licensed" : "Together: not licensed") : `Pooled: ${r.pooled.licensed ? "licensed" : "not licensed"}`}
        </span>
        <span className="muted text-sm" hidden={simple}>
          λ̂ {r.pooled.threshold}, {r.pooled.n} accepted, {r.pooled.k} wrong, U {pct(r.pooled.upper_bound, 2)}. Masked sum
          matches the direct sum: {r.sum_correct ? "yes" : "no"}.
        </span>
      </div>
      <p className="faint text-sm" hidden={simple}>This is a federation-level licence. Per-operator results are measurements, not guarantees.</p>
    </>
  );
}
