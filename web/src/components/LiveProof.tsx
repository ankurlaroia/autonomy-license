"use client";

import type { LiveEvidence, LiveUnit } from "@/lib/api";
import { pct } from "@/lib/api";
import { useSimple } from "@/lib/simple";

// What the deployed AWS stack did, read from the declared runs (judging.json and each run's record file). The console
// below is the local replay; this strip is the proof that the same policies held on the real Gateway. A rehearsal or a
// personal-account run says so: only runs in the team account are reported as results.
// `ev` undefined: still being read, so the strip holds its place; null: no declared run on record, so there is none.
const HEADING = {
  team: ["Declared runs in the team AWS account", "Declared runs on the real cloud system"],
  personal: ["Declared runs in a personal AWS account", "Declared runs in a personal cloud account"],
  rehearsal: ["Rehearsal in a personal AWS account, not a reported result", "Practice run in a personal cloud account, not a reported result"],
} as const;

export default function LiveProof({ ev }: { ev: LiveEvidence | undefined }) {
  const simple = useSimple();
  if (ev === undefined) return <LiveProofSkeleton />;
  if (!ev?.units) return null;
  const when = ev.when ? new Date(ev.when) : null;
  const real = ev.data_source === "telelogs";
  const count = (u: LiveUnit, word: string) => `${Math.round(u.value * u.items)} of ${u.items} ${word}`;
  const facts: { k: string; v: string; ok: boolean; run: string }[] = [];
  const { licence, allow, deny, adversarial, trace, pause } = ev.units;
  if (licence) facts.push({ k: simple ? "Worst-case wrong rate" : "Licence bound", v: pct(licence.value, 2), ok: licence.passed, run: licence.run_id });
  if (allow) facts.push({ k: simple ? "Small fixes" : "Live allow", v: count(allow, "allowed"), ok: allow.passed, run: allow.run_id });
  if (deny) facts.push({ k: simple ? "Changes too big" : "Live deny", v: count(deny, "denied"), ok: deny.passed, run: deny.run_id });
  if (adversarial) facts.push({ k: simple ? "Attacks tried" : "Live attacks", v: count(adversarial, "blocked"), ok: adversarial.passed, run: adversarial.run_id });
  if (trace) facts.push({ k: simple ? "Followed end to end" : "Rebuilt trace", v: count(trace, "complete"), ok: trace.passed, run: trace.run_id });
  if (pause) facts.push({ k: simple ? "After taking it away" : "Pause", v: count(pause, "refused"), ok: pause.passed, run: pause.run_id });
  const signer = ev.signer === "kms" ? "AWS KMS" : ev.signer ? "a local key" : null;

  return (
    <section className="glass mt-8 overflow-hidden" aria-label="Declared runs on AWS">
      <div className="flex flex-col gap-0 lg:flex-row">
        <div className="border-b border-[var(--line)] px-5 py-4 lg:w-[300px] lg:shrink-0 lg:border-r lg:border-b-0 sm:px-6">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={ev.scope === "team" ? "var(--signal)" : "currentColor"} strokeWidth="2" strokeLinecap="round" aria-hidden>
              <path d="M12 20v-6m-6 6a9 9 0 0112 0M3 10a13 13 0 0118 0M7.5 14a6.5 6.5 0 019 0" />
            </svg>
            {HEADING[ev.scope][simple ? 1 : 0]}
          </div>
          <p className="faint mt-1 text-caption leading-snug">
            {real ? "Real TeleLogs incidents" : ev.data_source ? "Synthetic stand-in data" : "Data source not on record"}
            {signer ? `, licence signed by ${signer}` : ""}
            {ev.policy_mode === "ENFORCE" ? ", Gateway enforcing" : ev.policy_mode ? `, Gateway ${ev.policy_mode}` : ""}
            {when ? `, ${when.toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}` : ""}
          </p>
        </div>
        <dl className="grid flex-1 grid-cols-2 sm:grid-cols-3">
          {facts.map((f) => (
            <div key={f.k} title={f.run} className="border-b border-[var(--line)] px-5 py-3 sm:border-r">
              <dt className="faint text-sm">{f.k}</dt>
              <dd className="mt-0.5 text-lg font-semibold tracking-tight" style={{ color: f.ok ? "var(--signal)" : "var(--ember)" }}>{f.v}{f.ok ? "" : ", missed target"}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}

function LiveProofSkeleton() {
  return (
    <section className="glass mt-8 overflow-hidden" aria-hidden>
      <div className="flex flex-col gap-0 lg:flex-row">
        <div className="space-y-2 border-b border-[var(--line)] px-5 py-4 lg:w-[300px] lg:shrink-0 lg:border-r lg:border-b-0 sm:px-6">
          <div className="skeleton h-5 w-3/4" /><div className="skeleton h-9 w-full" />
        </div>
        <div className="grid flex-1 grid-cols-2 sm:grid-cols-3">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="space-y-1.5 border-b border-[var(--line)] px-5 py-3 sm:border-r">
              <div className="skeleton h-4 w-2/3" /><div className="skeleton h-6 w-4/5" />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
