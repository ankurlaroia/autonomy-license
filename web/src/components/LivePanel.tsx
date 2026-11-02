"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { LiveCall, LiveHop, LiveKind, LiveStatus } from "@/lib/api";
import { api } from "@/lib/api";
import { useSimple } from "@/lib/simple";

// The Live view: real calls to the deployed AWS stack, and what each service recorded. Nothing here is computed in the
// browser or replayed: a step with no record yet says so. The network behind the tool is still the simulator.
const CALLS: { kind: LiveKind; label: string; simple: string; says: string; simpleSays: string }[] = [
  { kind: "small", label: "Small fix", simple: "Small fix", says: "2 cells, inside the licence", simpleSays: "A change the rules allow" },
  { kind: "big", label: "Lie about size", simple: "Hide a big change", says: "Every cell of the incident, claims 2", simpleSays: "Says it is small when it is not" },
  { kind: "split", label: "Split a big change", simple: "Sneak it in pieces", says: "3 cells, then 2 more", simpleSays: "A big change sent as small ones" },
  { kind: "tampered", label: "Tampered token", simple: "Forged pass", says: "Signature altered", simpleSays: "A login pass that was changed" },
];

const SERVICE: Record<string, string> = { interceptor: "Interceptor Lambda", tool: "Tool Lambda", "live-console": "This console" };
const KIND: Record<string, string> = {
  gateway_request: "Removed any claims from the agent, wrote the server's facts",
  tool_call: "Recorded the call before changing anything",
  remediation_applied: "Change applied to the simulated network",
  tool_refused: "Refused by the tool's own check",
};

const clock = (iso?: string | null) => (iso ? iso.slice(11, 23) : "");
const said = (v: unknown) => (typeof v === "boolean" ? (v ? "yes" : "no") : Array.isArray(v) ? (v.length ? v.join(", ") : "none") : String(v));

function isBlocked(c: LiveCall) {
  return c.decision !== "ALLOW";
}

export default function LivePanel({ onClose }: { onClose: () => void }) {
  const simple = useSimple();
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [last, setLast] = useState<LiveCall | null>(null);
  const [hops, setHops] = useState<LiveHop[]>([]);
  const [polling, setPolling] = useState(false);
  const [past, setPast] = useState<LiveCall[]>([]);
  const root = useRef<HTMLElement>(null);

  const refresh = useCallback(() => api.liveStatus().then(setStatus).catch((e) => setError((e as Error).message)), []);
  useEffect(() => {
    const first = setTimeout(() => void refresh(), 0);
    const t = setInterval(() => void refresh(), 10_000);     // the stack and licence can change from elsewhere
    root.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    return () => { clearTimeout(first); clearInterval(t); };
  }, [refresh]);

  // Records appear at once; CloudWatch lines some seconds later. Read until every record has its line, or 30 s.
  useEffect(() => {
    if (!last) return;
    let stop = false;
    const started = Date.now();
    const read = async () => {
      if (stop) return;
      try {
        const t = await api.liveTrace(last.trace_id);
        if (stop) return;
        setHops(t.hops);
        const done = last.gate.decision === "NOT_REACHED" || (t.hops.length > 0 && t.hops.every((h) => h.cloudwatch));
        if (done || Date.now() - started > 30_000) { setPolling(false); return; }
      } catch (e) {
        if (!stop) { setError((e as Error).message); setPolling(false); }
        return;
      }
      setTimeout(read, 2000);
    };
    setTimeout(read, 0);
    return () => { stop = true; };
  }, [last]);

  const act = useCallback(async (name: string, fn: () => Promise<LiveStatus>) => {
    setBusy(name);
    setError(null);
    try { setStatus(await fn()); } catch (e) { setError((e as Error).message); } finally { setBusy(null); }
  }, []);

  const send = useCallback(async (kind: LiveKind) => {
    setBusy(kind);
    setError(null);
    setHops([]);
    setLast(null);      // stops reading the previous trace, which must not end this one's wait
    if (last) setPast((p) => [last, ...p].slice(0, 5));
    try {
      const c = await api.liveCall(kind);
      setPolling(true);
      setLast(c);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }, [last]);

  const ready = !!status?.ready;
  const running = status?.stack === "running";
  const active = status?.licence?.status === "active";

  return (
    <section ref={root} className="glass reveal mt-8 scroll-mt-4 p-5 sm:p-7" aria-label="Live view of the AWS services">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-2xl font-semibold tracking-tight">{simple ? "Live on the real cloud system" : "Live on AWS"}</h2>
          <p className="muted mt-1 max-w-[68ch] text-sm leading-relaxed">
            {simple
              ? "These buttons send real requests to the real services, and you see what each one wrote down. The network behind them is still a simulator."
              : "Each button sends a real call through the deployed Gateway; each step below is what that service recorded. The network behind the tool is still the simulator, and these calls are recorded as undeclared, so they never count as a declared run."}
          </p>
        </div>
        <button type="button" className="lq-btn !min-h-[38px] text-sm" onClick={onClose}>Close</button>
      </div>

      {/* ---- what is true right now, read from AWS */}
      <dl className="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-[var(--line)] sm:grid-cols-4" aria-live="polite">
        <Fact k={simple ? "Services" : "Stack"} v={!status ? "Reading" : !ready ? "Unknown" : running ? "Running" : "Paused"} tone={running ? "signal" : undefined} />
        <Fact k={simple ? "Permission" : "Licence"} v={!status ? "Reading" : !ready ? "Unknown" : status.licence ? status.licence.status : "None"} tone={active ? "signal" : ready ? "ember" : undefined} sub={status?.licence?.jti.slice(0, 8)} />
        <Fact k={simple ? "Rules" : "Gateway policy"} v={status?.policy_mode === "ENFORCE" ? "Enforcing" : status?.policy_mode ?? "Reading"} />
        <Fact k={simple ? "Account" : "Account, region"} v={status?.account ? `…${status.account.slice(-4)}` : "Reading"} sub={status?.region} />
      </dl>
      {status?.reason && <p className="mt-3 text-sm" style={{ color: "var(--ember)" }} role="alert">{status.reason}</p>}
      {error && <p className="mt-3 text-sm" style={{ color: "var(--ember)" }} role="alert">{error}</p>}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {ready && !running && (
          <button type="button" className="lq-btn !min-h-[42px] text-sm" data-tone="signal" disabled={!!busy} onClick={() => void act("resume", api.liveResume)}>
            <Spin on={busy === "resume"} />{busy === "resume" ? "Turning on" : simple ? "Turn on the services" : "Turn on the stack"}
          </button>
        )}
        {ready && running && (
          <button type="button" className="lq-btn !min-h-[42px] text-sm" disabled={!!busy} onClick={() => void act("pause", api.livePause)}>
            <Spin on={busy === "pause"} />{busy === "pause" ? "Pausing" : simple ? "Pause the services" : "Pause the stack"}
          </button>
        )}
        {ready && active && (
          <button type="button" className="lq-btn !min-h-[42px] text-sm" data-tone="ember" disabled={!!busy} onClick={() => void act("withdraw", api.liveWithdraw)}>
            <Spin on={busy === "withdraw"} />{busy === "withdraw" ? "Withdrawing" : simple ? "Take the permission away" : "Withdraw the licence"}
          </button>
        )}
        {ready && !active && (
          <button type="button" className="lq-btn !min-h-[42px] text-sm" data-tone="signal" disabled={!!busy} onClick={() => void act("new", api.liveNewLicence)}>
            <Spin on={busy === "new"} />{busy === "new" ? "Calibrating and signing" : simple ? "Earn a new permission" : "Issue a new licence (KMS)"}
          </button>
        )}
      </div>

      {/* ---- send a real call */}
      <h3 className="mt-7 text-lg font-semibold tracking-tight">{simple ? "Try something" : "Send a real call"}</h3>
      {ready && !running && <p className="faint mt-1 text-sm">{simple ? "Turn the services on first." : "The stack is paused, so no call can run. Turn it on first; the first calls are slower while the Lambdas wake."}</p>}
      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {CALLS.map((c) => (
          <button key={c.kind} type="button" className="lq-btn !h-auto !min-h-[72px] !flex-col !items-start !justify-center !gap-0.5 !rounded-2xl !py-3 text-left"
            data-tone={c.kind === "small" ? "signal" : "ember"} disabled={!ready || !running || !!busy} onClick={() => void send(c.kind)}>
            <span className="flex items-center gap-2 text-sm font-semibold"><Spin on={busy === c.kind} />{simple ? c.simple : c.label}</span>
            <span className="muted text-caption font-normal">{simple ? c.simpleSays : c.says}</span>
          </button>
        ))}
      </div>

      {/* ---- what happened */}
      {last && <Trace call={last} hops={hops} polling={polling} simple={simple} />}

      {past.length > 0 && (
        <div className="mt-6">
          <h3 className="faint text-sm font-semibold">Earlier calls</h3>
          <ul className="mt-2 space-y-1 text-sm">
            {past.map((c) => (
              <li key={c.trace_id} className="flex flex-wrap gap-x-3">
                <span style={{ color: isBlocked(c) ? "var(--ember)" : "var(--signal)" }} className="font-semibold">{isBlocked(c) ? "Blocked" : "Allowed"}</span>
                <span>{CALLS.find((x) => x.kind === c.kind)?.label}</span>
                <span className="faint serial">{c.trace_id}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function Trace({ call, hops, polling, simple }: { call: LiveCall; hops: LiveHop[]; polling: boolean; simple: boolean }) {
  const blocked = isBlocked(call);
  const gate = call.gate;
  const gateLine = gate.decision === "FORBID" ? `Forbid${gate.policy ? `, policy ${gate.policy}` : ""}`
    : gate.decision === "PERMIT" ? "Permit" : gate.decision === "NOT_REACHED" ? "Not reached" : "No record yet";
  const before = hops.filter((h) => h.source === "interceptor");
  const after = hops.filter((h) => h.source !== "interceptor");
  return (
    <div className="mt-7">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="text-lg font-semibold tracking-tight" style={{ color: blocked ? "var(--ember)" : "var(--signal)" }} aria-live="polite">
          {blocked ? `Blocked: ${call.blocked_by}` : simple ? "Allowed, and the change was made" : "Allowed and applied"}
        </h3>
        <span className="faint serial">trace {call.trace_id}</span>
      </div>
      <p className="muted mt-1 text-sm">
        {call.incident}, {call.cells_sent} cells sent{call.claimed_cells != null ? `, the agent claimed ${call.claimed_cells}` : ""}
        {call.setup_cells != null ? `, after ${call.setup_cells} cells were sent first under ${call.trace_id}-setup` : ""}. Token {call.token_ms} ms, Gateway round trip {call.gateway_ms} ms.
      </p>
      <ol className="mt-4 space-y-2">
        <Step name="Your request" what={`Sent to the Gateway with a ${call.kind === "tampered" ? "tampered" : "real"} Cognito token`} at={call.sent_at} note="recorded by this console" ok />
        {before.map((h) => <RecordStep key={h.rec_id} h={h} polling={polling} />)}
        <Step name="Cedar policy" what={gateLine} note={gate.basis} ok={gate.decision === "PERMIT"} bad={gate.decision === "FORBID" || gate.decision === "NOT_REACHED"} />
        {after.map((h) => <RecordStep key={h.rec_id} h={h} polling={polling} />)}
        {polling && hops.length === 0 && <li className="faint text-sm">Reading the records from DynamoDB</li>}
        <Step name="Reply" what={blocked ? "Refused, nothing changed" : "Change confirmed"} at={call.replied_at} note="recorded by this console" ok={!blocked} bad={blocked} />
      </ol>
      {!polling && hops.some((h) => !h.cloudwatch) && <p className="faint mt-2 text-sm">Some CloudWatch lines had not arrived after 30 seconds. They usually follow shortly; the DynamoDB record stands on its own.</p>}
      {!blocked && <p className="faint mt-2 text-sm">The network is simulated, and whether a change resolved the fault comes from the data&rsquo;s known answer.</p>}
    </div>
  );
}

function RecordStep({ h, polling }: { h: LiveHop; polling: boolean }) {
  const refused = h.kind === "tool_refused";
  const fields = Object.entries(h.fields).filter(([k]) => k !== "reason");
  return (
    <Step name={SERVICE[h.source] ?? h.source} what={refused ? String(h.fields.reason) : KIND[h.kind] ?? h.kind} at={h.ts} ok={!refused} bad={refused}
      note={h.cloudwatch ? `DynamoDB record; CloudWatch ${clock(h.cloudwatch)}` : polling ? "DynamoDB record; waiting for CloudWatch" : "DynamoDB record"}
      fields={fields.map(([k, v]) => `${k.replaceAll("_", " ")}: ${said(v)}`).join(", ")} />
  );
}

function Step({ name, what, at, note, fields, ok, bad }: { name: string; what: string; at?: string | null; note?: string; fields?: string; ok?: boolean; bad?: boolean }) {
  const color = bad ? "var(--ember)" : ok ? "var(--signal)" : "var(--frost-3)";
  return (
    <li className="glass-card grid grid-cols-[10px_1fr] gap-3 px-4 py-3 sm:grid-cols-[10px_170px_1fr_auto]">
      <span className="mt-1.5 h-2.5 w-2.5 rounded-full" style={{ background: color }} aria-hidden />
      <span className="text-sm font-semibold">{name}</span>
      <span className="col-start-2 min-w-0 text-sm sm:col-start-3">
        {what}
        {fields && <span className="faint block text-caption">{fields}</span>}
        {note && <span className="faint block text-caption">{note}</span>}
      </span>
      {at && <span className="faint serial col-start-2 sm:col-start-4 sm:text-right">{clock(at)}</span>}
    </li>
  );
}

function Fact({ k, v, sub, tone }: { k: string; v: string; sub?: string; tone?: "signal" | "ember" }) {
  return (
    <div className="bg-sink px-4 py-3">
      <dt className="faint text-sm">{k}</dt>
      <dd className="mt-0.5 text-lg font-semibold capitalize tracking-tight" style={{ color: tone ? `var(--${tone})` : undefined }}>{v}</dd>
      {sub && <dd className="faint serial normal-case">{sub}</dd>}
    </div>
  );
}

function Spin({ on }: { on: boolean }) {
  if (!on) return null;
  return <svg className="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden><path d="M12 3a9 9 0 019 9" strokeLinecap="round" /></svg>;
}
