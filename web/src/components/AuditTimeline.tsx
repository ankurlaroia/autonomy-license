"use client";

import { policyName } from "@/components/Decision";
import type { AuditRow } from "@/lib/api";
import { pct } from "@/lib/api";

// The audit trail as a timeline, newest first, exactly as the engine recorded it. Entries written within a second
// of each other are one moment's work, so the time is shown once per burst and bursts are spaced apart. Licence
// events (issued, revoked, warned) are milestones; everything else is a step on the rail, coloured by outcome.
type Tone = "signal" | "ember" | "amber" | undefined;
type D = Record<string, unknown> & {
  decision?: string; policies?: string[]; tool?: string; role?: string; action?: string; cells?: unknown;
  mode?: string; category?: string; jti?: string; approval_id?: string; issuer?: string; exp?: number;
  threshold?: number; n?: number; k?: number; upper_bound?: number; errors?: number; e_value?: number;
};

const words = (s: unknown) => String(s ?? "").replaceAll("_", " ");
const cellCount = (c: unknown) => (Array.isArray(c) ? c.length : typeof c === "number" ? c : null);
const clock = (ts: number) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

function describe(r: AuditRow): { label: string; tone: Tone; milestone?: boolean; text: string } {
  const d = r.detail as D;
  const cells = cellCount(d.cells);
  switch (r.kind) {
    case "policy_decision":
      return { label: d.decision === "ALLOW" ? "Allowed" : "Denied", tone: d.decision === "ALLOW" ? "signal" : "ember",
        text: `${words(d.role)} asked to ${words(d.tool)}` };
    case "remediation_applied":
      return { label: "Change applied", tone: "signal",
        text: `${words(d.action)}${cells != null ? ` on ${cells} cell${cells === 1 ? "" : "s"}` : ""}${d.mode ? `, ${d.mode}` : ""}${d.category ? `, ${d.category}` : ""}` };
    case "tool_refused":
      return { label: "Refused by tool re-check", tone: "ember", text: words(d.action ?? d.tool) };
    case "approval_requested":
      return { label: "Approval requested", tone: "amber",
        text: `${words(d.action)}${cells != null ? `, ${cells} cell${cells === 1 ? "" : "s"}` : ""}${d.approval_id ? `, ${d.approval_id}` : ""}` };
    case "approval_decided":
      return { label: "Approval decided", tone: "amber", text: `${words(d.action)}${d.approval_id ? `, ${d.approval_id}` : ""}` };
    case "licence_issued":
      return { label: "Licence issued", tone: "signal", milestone: true,
        text: `acts alone at ≥ ${d.threshold?.toFixed(2) ?? "?"}; ${d.n} cases, ${d.k} wrong; bound ${pct(d.upper_bound ?? null, 2)}` };
    case "licence_revoked":
      return { label: "Licence revoked", tone: "ember", milestone: true, text: "withdrawn by a person; the next action goes to an engineer" };
    case "licence_auto_revoked":
      return { label: "Licence revoked itself", tone: "ember", milestone: true,
        text: `outcomes after acting: ${d.errors} wrong of ${d.n} watched, e-value ${d.e_value}` };
    case "warning_received":
      return { label: "Warning received", tone: "amber", milestone: true,
        text: `from operator ${d.issuer} about ${d.category}${d.exp ? `, in force until ${clock(d.exp)}` : ""}` };
    default:
      return { label: words(r.kind), tone: undefined, text: "" };
  }
}

const COLOR: Record<string, string> = { signal: "var(--signal)", ember: "var(--ember)", amber: "var(--amber)" };

export default function AuditTimeline({ rows }: { rows: AuditRow[] }) {
  return (
    <ol className="scroll-fade mt-4 max-h-[460px] overflow-y-auto pr-1" aria-label="Audit trail, newest first">
      {rows.map((r, i) => {
        const prev = rows[i - 1];
        const newBurst = !prev || Math.abs(prev.ts - r.ts) >= 1;
        const sameIncident = prev && !newBurst && prev.incident === r.incident;
        const { label, tone, milestone, text } = describe(r);
        const color = tone ? COLOR[tone] : "var(--frost-3)";
        const policies = ((r.detail as D).policies ?? []) as string[];
        return (
          <li key={r.seq} className={`timeline-row ${newBurst && i > 0 ? "mt-3" : ""}`} data-milestone={milestone || undefined}
            style={{ "--tone": color } as React.CSSProperties}>
            <span className="faint text-caption tabular-nums">{newBurst ? clock(r.ts) : ""}</span>
            <span className="timeline-node" aria-hidden />
            <div className="min-w-0 py-1.5">
              <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 text-sm">
                <b style={{ color: tone && (milestone || r.kind === "policy_decision") ? color : undefined }}>{label}</b>
                {policies.map((p) => <span key={p} className="faint font-semibold" title={policyName(p)}>{p}</span>)}
                <span className="muted min-w-0">{text}</span>
              </div>
            </div>
            <span className="faint hidden text-caption tabular-nums sm:block" title={r.incident || undefined}>
              {r.incident && !sameIncident ? r.incident.replace("sha256:", "").slice(0, 8) : ""}
              <span className="ml-2 opacity-70">#{r.seq}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}
