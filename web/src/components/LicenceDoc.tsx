"use client";

import { motion, useReducedMotion } from "motion/react";
import type { ReactNode } from "react";

import type { AuditRow, Licence } from "@/lib/api";
import { pct } from "@/lib/api";
import { EASE_OUT, type Ceremony, useTyped } from "@/lib/ceremony";
import { useSimple } from "@/lib/simple";

// The licence as the document it is: an operating permit with security engraving, a serial, the signature
// method and a seal whose ring shows how much of the error budget (alpha) the certified bound U uses.
// The seal stamps in once per new licence; a withdrawn licence gets a REVOKED stamp across it. During the issuing
// ceremony (lib/ceremony.ts) the serial types in, each field fills as its value is decided, the seal lands when the
// test ends and its ring draws to the real U / alpha.

function rosette(cx: number, cy: number, R: number, r: number, d: number, turns: number, steps = 900) {
  const pts: string[] = [];
  for (let i = 0; i <= steps; i++) {
    const t = (i / steps) * turns * 2 * Math.PI;
    const x = cx + (R - r) * Math.cos(t) + d * Math.cos(((R - r) / r) * t);
    const y = cy + (R - r) * Math.sin(t) - d * Math.sin(((R - r) / r) * t);
    pts.push(`${x.toFixed(1)},${y.toFixed(1)}`);
  }
  return "M" + pts.join("L");
}
// Security engraving: two interleaved hypotrochoid rosettes and a wave band, drawn once.
const GUILLOCHE = [rosette(330, 120, 150, 29, 62, 29), rosette(330, 120, 110, 17, 40, 17)];
const WAVES = Array.from({ length: 9 }, (_, k) => {
  const pts = Array.from({ length: 121 }, (_, i) => {
    const x = i * 4;
    return `${x},${(18 + k * 3.2 + 5 * Math.sin(i / 6 + k * 0.7)).toFixed(1)}`;
  });
  return "M" + pts.join("L");
});

// A licence's history, read from the audit trail: how and when this licence was withdrawn, and which revoked licence
// it replaced. Revoke and re-issue are then one object's story: the card says it was withdrawn, and its successor
// says what it supersedes, with the old sheet left visible underneath.
type Revocation = { jti: string; by: "person" | "evidence"; ts: number };
export type LicenceHistory = { revoked: Revocation | null; supersedes: Revocation | null };

export function licenceHistory(audit: AuditRow[], licence: Licence | null): LicenceHistory {
  if (!licence) return { revoked: null, supersedes: null };
  const revs: (Revocation & { seq: number })[] = audit
    .filter((r) => r.kind === "licence_revoked" || r.kind === "licence_auto_revoked")
    .map((r) => ({ jti: String(r.detail.jti), by: r.kind === "licence_revoked" ? "person" : "evidence", ts: r.ts, seq: r.seq }));
  // It supersedes the licence issued just before it, and only if that one had been revoked by then; a predecessor
  // still active (the self-revoke moment's proven licence) is not superseded, so nothing is claimed.
  const issues = audit.filter((r) => r.kind === "licence_issued").sort((a, b) => a.seq - b.seq);
  const at = issues.findIndex((r) => r.detail.jti === licence.jti);
  const prev = at > 0 ? issues[at - 1] : undefined;
  const before = prev && revs.find((v) => v.jti === prev.detail.jti && v.seq < issues[at].seq);
  return { revoked: revs.find((v) => v.jti === licence.jti) ?? null, supersedes: before ?? null };
}

const hm = (ts: number) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
const withdrawn = (v: Revocation, simple: boolean) =>
  v.by === "person" ? `${simple ? "Taken away" : "Withdrawn"} at ${hm(v.ts)} by a person` : `Revoked itself at ${hm(v.ts)} on the evidence`;

function expiresIn(exp: number, now: number) {
  const s = Math.max(0, exp - now / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return s <= 0 ? "Expired" : h ? `${h} h ${m} min left` : `${m} min left`;
}

function Seal({ licence, at }: { licence: Licence; at: number | null }) {
  const reduce = useReducedMotion();
  const R = 44;
  const C = 2 * Math.PI * R;
  const used = Math.min(licence.risk.upper_bound / licence.risk.alpha, 1);
  const draw = at != null && !reduce;
  return (
    <svg key={licence.jti} viewBox="0 0 120 120" className="stamp-in h-[112px] w-[112px]" role="img"
      style={at != null ? { animationDelay: `${at}s` } : undefined}
      aria-label={`Certified error bound ${pct(licence.risk.upper_bound, 2)} of a ${pct(licence.risk.alpha, 0)} budget`}>
      <defs>
        <path id="seal-text" d="M60,60 m-52,0 a52,52 0 1,1 104,0 a52,52 0 1,1 -104,0" />
      </defs>
      <circle cx="60" cy="60" r="57" fill="var(--seal)" fillOpacity="0.06" stroke="var(--seal)" strokeOpacity="0.5" />
      <text fontSize="7.4" fontWeight="700" fill="var(--seal)" letterSpacing="2.4">
        <textPath href="#seal-text">CERTIFIED BOUND · FIXED-SEQUENCE TEST · SIGNED ·</textPath>
      </text>
      <circle cx="60" cy="60" r={R} fill="none" stroke="var(--seal)" strokeOpacity="0.14" strokeWidth="6" />
      <motion.circle className={draw ? undefined : "ring-arc"} cx="60" cy="60" r={R} fill="none" stroke="var(--seal)" strokeWidth="6"
        strokeLinecap="round" strokeDasharray={C} transform="rotate(-90 60 60)"
        initial={draw ? { strokeDashoffset: C } : false} animate={{ strokeDashoffset: C * (1 - used) }}
        transition={draw ? { delay: at + 0.3, duration: 0.9, ease: EASE_OUT } : { duration: 1.2, ease: EASE_OUT }} />
      <text x="60" y="60" textAnchor="middle" fontSize="17" fontWeight="800" fill="var(--paper-ink)">{pct(licence.risk.upper_bound, 2)}</text>
      <text x="60" y="74" textAnchor="middle" fontSize="8" fill="var(--paper-ink)" fillOpacity="0.65">of {pct(licence.risk.alpha, 0)} budget</text>
    </svg>
  );
}

// One field of the licence, filling in at the moment its value is decided (`at`: null shows it at once).
function Fill({ i, at, className, children }: { i: number; at: number | null; className?: string; children: ReactNode }) {
  return (
    <motion.div className={className} initial={at != null ? { opacity: 0, y: 6 } : false} animate={{ opacity: 1, y: 0 }}
      transition={{ delay: (at ?? 0) + i * 0.09, duration: 0.4, ease: EASE_OUT }}>
      {children}
    </motion.div>
  );
}

// `conn` says whether "no licence" is known: while the engine is loading or unreachable the register can't be read,
// and the card says so rather than "not issued".
export default function LicenceDoc({ licence, warned, now, ceremony, conn = "ok", history }: {
  licence: Licence | null; warned: string[]; now: number | null; ceremony?: Ceremony | null; conn?: "loading" | "ok" | "down";
  history?: LicenceHistory;
}) {
  const simple = useSimple();
  const reduce = useReducedMotion();
  const state = !licence ? "none" : licence.status === "active" ? "active" : "revoked";
  const serial = licence ? `No. ${licence.jti.slice(0, 8).toUpperCase()}` : "";
  const typed = useTyped(serial, 0.15);
  const play = !!ceremony && !reduce;
  const fillAt = play ? ceremony!.decided : null;

  if (!licence) {
    return (
      <article className="licence mx-auto w-full max-w-[440px] p-7" data-state="none" aria-busy={conn === "loading"}
        aria-label={conn === "ok" ? "No licence issued" : conn === "loading" ? "Reading the licence" : "Licence unknown: engine unreachable"}>
        <p className="faint text-sm">Operating licence for autonomous remediation</p>
        <h2 className="engraved mt-1 text-4xl leading-none text-[var(--frost)]">Autonomy Licence</h2>
        <dl className="mt-7 grid grid-cols-2 gap-x-6 gap-y-4">
          {["Acts alone at confidence", "Error bound", "Evidence", "Valid for"].map((k) => (
            <div key={k}><dt>{k}</dt><dd className={`mt-1 h-4 w-20 rounded ${conn === "loading" ? "skeleton" : "bg-fg/[.06]"}`} /></div>
          ))}
        </dl>
        <p className="mt-8 text-body leading-relaxed">
          {conn === "loading" ? <span className="late block">Reading the licence register from the engine.</span>
            : conn === "down" ? (simple ? "Unknown while the engine is offline. Nothing can act alone until it is back."
              : "Unknown: the engine is unreachable, so no licence can be read or checked. Nothing acts alone until it answers.")
            : simple ? "Not issued yet. Press Earn: the AI is tested first, and only a pass earns a licence."
            : "Not issued. Press Earn to calibrate on held-back incidents; a licence is signed only if the bound fits the budget."}
        </p>
      </article>
    );
  }

  const r = licence.risk;
  const cats = licence.scope.categories;
  const revoked = history?.revoked ?? null;
  const prior = history?.supersedes ?? null;
  return (
    <div className={`relative mx-auto w-full max-w-[440px] ${prior ? "pt-8" : ""}`}>
    {prior && (
      // the licence this one replaced: the sheet underneath, lifting back as the new one lands
      <div key={prior.jti} aria-hidden className={`licence licence-under ${play ? "lift-back" : ""}`} data-state="revoked">
        <div className="flex items-center justify-between gap-3 px-6 pt-2 text-caption font-semibold">
          <span className="serial" style={{ color: "rgb(28 42 56 / 0.6)" }}>No. {prior.jti.slice(0, 8).toUpperCase()}</span>
          <span style={{ color: "#b4322a" }}>Revoked</span>
        </div>
      </div>
    )}
    <article key={licence.jti} className="licence relative w-full" data-state={state}
      aria-label={`Autonomy licence ${licence.jti.slice(0, 8)}, ${state}`}>
      <svg className="pointer-events-none absolute inset-0 -z-10 h-full w-full" viewBox="0 0 440 560" preserveAspectRatio="xMidYMin slice" aria-hidden>
        {GUILLOCHE.map((d, i) => <path key={i} d={d} fill="none" stroke="var(--seal)" strokeOpacity={i ? 0.10 : 0.075} strokeWidth="0.6" />)}
        <g transform="translate(0 470)">{WAVES.map((d, i) => <path key={i} d={d} fill="none" stroke="var(--seal)" strokeOpacity="0.09" strokeWidth="0.6" />)}</g>
      </svg>

      <header className="border-b border-[rgb(28_42_56/0.14)] px-7 pt-6 pb-4">
        <div className="flex items-center justify-between gap-3 text-caption font-semibold" style={{ color: "var(--seal)" }}>
          <span>Operating licence for autonomous remediation</span>
          <span className="serial shrink-0 whitespace-nowrap" title={licence.jti} aria-label={serial}>
            {play ? typed : serial}<span aria-hidden className="invisible">{play ? serial.slice(typed.length) : ""}</span>
          </span>
        </div>
        <h2 className="engraved mt-1.5 text-4xl leading-[0.95]">Autonomy Licence</h2>
        <p className="mt-1.5 text-sm" style={{ color: "rgb(28 42 56 / 0.7)" }}>
          {simple ? "Lets the network AI fix these faults on its own, until it expires or is withdrawn."
            : `Granted to the NetOps agent for operator${licence.scope.operators.length > 1 ? "s" : ""} ${licence.scope.operators.join(", ")}.`}
        </p>
        {prior && (
          <p className="mt-1.5 text-caption" style={{ color: "rgb(28 42 56 / 0.7)" }}>
            {simple ? "Replaces" : "Supersedes"} <span className="serial">No. {prior.jti.slice(0, 8).toUpperCase()}</span>, {withdrawn(prior, simple).replace(/^./, (c) => c.toLowerCase())}.
          </p>
        )}
      </header>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 px-7 pt-5">
        <Fill i={0} at={fillAt}><dt>{simple ? "Must be at least this sure" : "Acts alone at confidence"}</dt><dd>{simple ? `${Math.round(r.threshold * 100)}%` : `≥ ${r.threshold.toFixed(2)}`}</dd></Fill>
        <Fill i={1} at={fillAt}><dt>{simple ? "Tested on" : "Calibration evidence"}</dt><dd>{r.n} cases, {r.k} wrong</dd></Fill>
        <Fill i={2} at={fillAt}><dt>{simple ? "Licence ends" : "Valid for"}</dt><dd>{state === "revoked" ? (revoked ? withdrawn(revoked, simple) : "Withdrawn") : now ? expiresIn(licence.exp, now) : "…"}</dd></Fill>
        <Fill i={3} at={fillAt}><dt>{simple ? "Sure the bound holds" : "Confidence in the bound"}</dt><dd>{pct(1 - r.delta, 0)}</dd></Fill>
        <Fill i={4} at={fillAt} className="col-span-2">
          <dt>{simple ? "Fault types covered" : "Licensed categories"}</dt>
          <dd className="mt-1 flex flex-wrap gap-1.5">
            {cats.map((c) => (
              <span key={c} className="rounded-md border px-2 py-0.5 text-caption"
                style={warned.includes(c)
                  ? { borderColor: "rgb(180 50 42 / .5)", color: "#b4322a", textDecoration: "line-through" }
                  : { borderColor: "rgb(18 117 102 / .35)", color: "var(--seal)" }}
                title={warned.includes(c) ? "Paused by a signed warning from another operator" : undefined}>
                {c}
              </span>
            ))}
          </dd>
        </Fill>
      </dl>

      <footer className="mt-4 flex items-end justify-between gap-4 px-7 pb-6">
        <div className="min-w-0">
          <div className="engraved text-xl italic leading-none" style={{ color: "var(--seal)" }}>calibration authority</div>
          <div className="mt-1 border-t border-[rgb(28_42_56/0.35)] pt-1 text-caption" style={{ color: "rgb(28 42 56 / 0.6)" }}>
            Signed ES256. Pre-registered thresholds, fixed-sequence Clopper–Pearson.
          </div>
        </div>
        <Seal licence={licence} at={play ? ceremony!.seal : null} />
      </footer>

      {state === "revoked" && <div key={licence.jti + "void"} className="void stamp-in" role="status">REVOKED</div>}
    </article>
    </div>
  );
}
