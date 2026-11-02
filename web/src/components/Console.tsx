"use client";

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

import AuditTimeline from "@/components/AuditTimeline";
import Backdrop from "@/components/Backdrop";
import Decision from "@/components/Decision";
import LicenceDoc, { licenceHistory } from "@/components/LicenceDoc";
import LivePanel from "@/components/LivePanel";
import LiveProof from "@/components/LiveProof";
import TopBar from "@/components/TopBar";
import { ceremony } from "@/lib/ceremony";
import { useSimple } from "@/lib/simple";
import type { AlphaRow, LiveEvidence, MomentId, State } from "@/lib/api";
import { MOMENTS, api, pct } from "@/lib/api";

const MOOD: Record<MomentId, "allow" | "deny" | "human" | "revoked"> = {
  earn: "allow", act: "allow", block: "deny", revoke: "revoked", recertify: "allow", federation: "allow", warning: "human", self_revoke: "allow",   // a self-revoked licence is caught by the status check below
};

export default function Console() {
  const [state, setState] = useState<State | null>(null);
  const [alphas, setAlphas] = useState<AlphaRow[]>([]);
  const [pick, setPick] = useState(0.05);
  const [busy, setBusy] = useState<MomentId | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pulse, setPulse] = useState(0);
  const [now, setNow] = useState<number | null>(null);
  const [live, setLive] = useState<LiveEvidence | undefined>(undefined);   // undefined: not read yet
  const [liveOn, setLiveOn] = useState(false);     // the API has the Live view switched on (AL_LIVE=1, this machine only)
  const [liveOpen, setLiveOpen] = useState(false);
  const [stage, setStage] = useState(false);
  const [seen, setSeen] = useState<MomentId[]>([]);
  const [resetting, setResetting] = useState(false);
  const [armed, setArmed] = useState(false);   // R was pressed once; a second R within 3 s resets
  // Whether the engine answers. Everything on screen comes from it, so until it does the console shows no licence
  // facts and offers no moments: loading, then either the console or the engine-down panel.
  const [conn, setConn] = useState<"loading" | "ok" | "down">("loading");
  const [checking, setChecking] = useState(false);

  const loadAlphas = useCallback(() => api.alphas().then((a) => { setAlphas(a.alphas); setPick(a.official_alpha); }), []);

  const connect = useCallback(async () => {
    setChecking(true);
    try {
      setState(await api.state());
      setConn("ok");
      setError(null);
      loadAlphas().catch(() => {});
      api.evidence().then((e) => setLive(e.live)).catch(() => setLive(null));
      api.liveStatus().then((s) => setLiveOn(s.enabled === true)).catch(() => setLiveOn(false));
    } catch {
      setConn("down");
    } finally {
      setChecking(false);
    }
  }, [loadAlphas]);

  // A failed moment is either the engine refusing (show its message) or the engine gone (show the down panel).
  const failed = useCallback(async (e: unknown) => {
    const gone = await api.state().then(() => false, () => true);
    if (gone) setConn("down");
    else setError((e as Error).message);
  }, []);

  useEffect(() => {
    const first = setTimeout(() => void connect(), 0);
    return () => clearTimeout(first);
  }, [connect]);
  // While the engine is down, look again every 4 s, so starting it brings the console back by itself.
  useEffect(() => {
    if (conn !== "down") return;
    const t = setInterval(() => void connect(), 4000);
    return () => clearInterval(t);
  }, [conn, connect]);

  useEffect(() => {
    const tick = () => setNow(Date.now());
    const first = setTimeout(tick, 0);
    const t = setInterval(tick, 30_000);
    return () => { clearTimeout(first); clearInterval(t); };
  }, [loadAlphas]);

  const licensed = !!state?.licence;
  const active = state?.licence?.status === "active";
  const run = useCallback(async (m: MomentId) => {
    if (busy || resetting || conn !== "ok") return;
    setBusy(m);
    setError(null);
    try {
      setState(await api.run(m));
      setPulse((p) => p + 1);
      setSeen((s) => (s.includes(m) ? s : [...s, m]));
      if (m === "earn" || m === "recertify") loadAlphas().catch(() => {});
    } catch (e) {
      await failed(e);
    } finally {
      setBusy(null);
    }
  }, [busy, resetting, conn, loadAlphas, failed]);

  // Start the demo over, as restarting the API does: no licence, no warning in force, an empty audit trail.
  const resetDemo = useCallback(async () => {
    setArmed(false);
    if (busy || resetting) return;
    setResetting(true);
    setError(null);
    try {
      setState(await api.reset());
      setSeen([]);
      setPulse((p) => p + 1);
    } catch (e) {
      await failed(e);
    } finally {
      setResetting(false);
    }
  }, [busy, resetting, failed]);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 3000);
    return () => clearTimeout(t);
  }, [armed]);

  // Stage mode: the console on a projector. Full screen where the browser allows it; the stylesheet scales the type
  // to the screen (html[data-stage]).
  const enterStage = useCallback(() => {
    setStage(true);
    document.documentElement.requestFullscreen?.().catch(() => {});
  }, []);
  const leaveStage = useCallback(() => {
    setStage(false);
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  }, []);
  useLayoutEffect(() => {
    if (!stage) return;
    const root = document.documentElement;
    root.dataset.stage = "";
    window.scrollTo(0, 0);
    // In full screen the browser keeps Esc for itself, so leaving full screen leaves stage mode too.
    const onFull = () => { if (!document.fullscreenElement) setStage(false); };
    document.addEventListener("fullscreenchange", onFull);
    return () => { document.removeEventListener("fullscreenchange", onFull); delete root.dataset.stage; };
  }, [stage]);

  const lastName = state?.last?.name ?? null;
  // On a phone the dock scrolls sideways: keep the next step in view, so the next tap needs no hunting.
  const dock = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const d = dock.current;
    const next = nextMoment(lastName, active);
    const b = next && d?.querySelector<HTMLElement>(`[data-moment="${next}"]`);
    if (d && b && d.scrollWidth > d.clientWidth) d.scrollTo({ left: b.offsetLeft - (d.clientWidth - b.offsetWidth) / 2, behavior: "smooth" });
  }, [lastName, active]);
  // Number keys 1–7 run the numbered moments; S enters or leaves stage mode; R twice resets the demo (twice, so
  // a stray key can't wipe it mid-talk). On stage, → / PageDown (what a presenter clicker sends) / Space run the
  // next moment in the demo order, and Esc leaves.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || e.repeat) return;
      const el = e.target as HTMLElement | null;
      if (el?.closest("input, textarea, select, [contenteditable]")) return;
      if (e.key === "s" || e.key === "S") return stage ? leaveStage() : enterStage();
      if (stage && e.key === "Escape") return leaveStage();
      if (e.key === "r" || e.key === "R") return armed ? void resetDemo() : setArmed(true);
      if (stage && (e.key === "ArrowRight" || e.key === "PageDown" || (e.key === " " && !el?.closest("button, a")))) {
        e.preventDefault();
        const next = nextMoment(lastName, active);
        if (next) run(next);
        return;
      }
      const m = MOMENTS.find((x) => String(x.n) === e.key);
      if (m && (!m.needsLicence || active)) run(m.id);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [run, active, stage, lastName, enterStage, leaveStage, armed, resetDemo]);

  const lic = state?.licence ?? null;
  const history = licenceHistory(state?.licence_events ?? [], lic);
  const mood = lic?.status === "revoked" ? "revoked" : state?.last ? MOOD[state.last.name] : "idle";
  const a = alphas.find((x) => x.alpha === pick);
  const simple = useSimple();
  const warned = state?.warned_categories ?? [];
  // A licence that was just issued gets its ceremony, timed to the calibration chart that issued it.
  const last = state?.last;
  const issuing = last?.name === "earn" ? ceremony(last.result?.calibration?.trace?.length ?? 0)
    : last?.name === "recertify" ? ceremony(0) : null;

  // Each moment on stage gets the largest type that still fits the screen: the stylesheet's size for this screen,
  // stepped down only as far as this moment needs.
  useLayoutEffect(() => {
    if (!stage) return;
    const root = document.documentElement;
    const fit = () => {
      root.style.removeProperty("font-size");
      let fs = parseFloat(getComputedStyle(root).fontSize);
      while (root.scrollHeight > innerHeight + 1 && fs > 12) {
        fs -= 0.5;
        root.style.fontSize = `${fs}px`;
      }
    };
    fit();
    window.addEventListener("resize", fit);
    return () => { window.removeEventListener("resize", fit); root.style.removeProperty("font-size"); };
  }, [stage, pulse, simple, error]);

  // On stage the licence never moves; beside it, the opening statement, then one moment at a time.
  if (stage) {
    return (
      <>
        <Backdrop mood={mood} pulse={pulse} />
        <div className="stage">
          <StageBar last={lastName} seen={seen} onExit={leaveStage} />
          {error && <ErrorBar message={error} onDismiss={() => setError(null)} />}
          <main className="stage-main">
            <LicenceDoc licence={lic} warned={warned} now={now} ceremony={issuing} conn={conn} history={history} />
            {conn === "down" ? (
              <div className="glass min-w-0"><EngineDown checking={checking} onRetry={() => void connect()} /></div>
            ) : last ? (
              <div className="glass min-w-0" aria-live="polite">
                <Decision last={last} alpha={lic?.risk.alpha ?? 0.05} run={pulse} />
              </div>
            ) : (
              <Pitch status={lic?.status ?? null} />
            )}
          </main>
          <StageFoot next={nextMoment(lastName, active)} busy={busy} resetting={resetting} armed={armed} />
        </div>
      </>
    );
  }

  return (
    <>
      <Backdrop mood={mood} pulse={pulse} />

      <div className="mx-auto max-w-[1240px] px-4 pb-40 pt-5 sm:px-6">
        <TopBar active="console" source={state?.data_source} onStage={enterStage}
          onLive={liveOn ? () => setLiveOpen((o) => !o) : undefined} liveOpen={liveOpen} />

        {error && <div className="mt-4"><ErrorBar message={error} onDismiss={() => setError(null)} /></div>}

        {/* ------------------------------------------------ hero: the licence itself */}
        <section className="mt-8 grid grid-cols-1 items-center gap-10 lg:grid-cols-[440px_1fr] lg:gap-14">
          <LicenceDoc licence={lic} warned={warned} now={now} ceremony={issuing} conn={conn} history={history} />
          <Pitch status={lic?.status ?? null} />
        </section>

        <LiveProof ev={conn === "down" ? null : live} />
        {liveOn && liveOpen && <LivePanel onClose={() => setLiveOpen(false)} />}

        {/* ------------------------------------------------ stage + side */}
        <section className="mt-10 grid grid-cols-1 gap-5 lg:grid-cols-[1fr_340px]">
          <div className="glass min-w-0" aria-live="polite" aria-busy={conn === "loading"}>
            {conn === "loading" ? <DecisionSkeleton />
              : conn === "down" ? <EngineDown checking={checking} onRetry={() => void connect()} />
              : (
                <>
                  <Decision last={state?.last ?? null} alpha={lic?.risk.alpha ?? 0.05} run={pulse} />
                  <NextStep last={state?.last?.name ?? null} licensed={active} busy={!!busy || resetting} running={busy} run={run}
                    armed={armed} onReset={resetDemo} />
                </>
              )}
          </div>

          <aside className="space-y-5">
            <div className="glass p-5">
              <h2 className="text-lg font-semibold tracking-tight">{simple ? "Waiting for a person" : "Waiting for an engineer"}</h2>
              {conn !== "ok" ? (
                <Lines bars={["mt-2 h-5"]} conn={conn} />
              ) : state?.approvals.length ? (
                <ul className="mt-3 space-y-2">
                  {state.approvals.map((p) => (
                    <li key={p.id} className="glass-card px-4 py-3">
                      <div className="flex items-center justify-between gap-2">
                        <b className="text-sm">{p.action.replaceAll("_", " ")}</b>
                        <span className="pill">{p.cells} cells</span>
                      </div>
                      <p className="faint mt-1 text-xs" title={`${p.id}: ${p.reason}`}>{approvalWhy(p.reason)}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted mt-2 text-sm">No changes are waiting for approval.</p>
              )}
            </div>

            <div className="glass p-5" hidden={simple}>
              <h2 className="text-lg font-semibold tracking-tight">Try another error budget</h2>
              <p className="faint mt-1 text-sm">Only the pre-registered budget is certified. Others are for exploring.</p>
              {!alphas.length ? <Lines bars={["mt-4 h-[52px] !rounded-full", "mt-4 h-[112px]"]} conn={conn === "ok" ? "loading" : conn} /> : (
              <div role="radiogroup" aria-label="Error budget α" className="mt-4 flex gap-1.5 rounded-full bg-sink p-1.5">
                {alphas.map((x) => (
                  <button key={x.alpha} role="radio" aria-checked={pick === x.alpha}
                    className="lq-btn flex-1 !min-h-[40px] !px-2 text-sm" data-tone={x.official ? "signal" : undefined}
                    onClick={() => setPick(x.alpha)}>
                    {pct(x.alpha, 0)}
                  </button>
                ))}
              </div>
              )}
              {a && (
                <div className="mt-4">
                  <span className="pill" data-tone={a.official ? "signal" : "amber"}>{a.official ? "Certified" : "Exploratory, not certified"}</span>
                  {a.licensed ? (
                    <dl className="mt-3 grid grid-cols-3 divide-x divide-[rgb(var(--line-rgb)/0.16)] border-y border-[rgb(var(--line-rgb)/0.16)] text-center">
                      <Fact k="λ" v={a.threshold?.toFixed(2) ?? "—"} />
                      <Fact k="Alone" v={pct(a.heldout_autonomy)} />
                      <Fact k="Wrong" v={pct(a.heldout_error, 1)} />
                    </dl>
                  ) : (
                    <p className="muted mt-3 text-sm">Not enough evidence to license at this budget.</p>
                  )}
                </div>
              )}
            </div>
          </aside>
        </section>

        {/* ------------------------------------------------ audit */}
        <section className="glass mt-5 p-5 sm:p-7">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="text-lg font-semibold tracking-tight">{simple ? "Permanent record" : "Audit trail"}</h2>
            <span className="faint text-sm">{simple ? "Nothing can be edited or deleted." : "Append-only. Incident ids are hashed."}</span>
          </div>
          {simple ? (
            <p className="muted mt-3 text-sm">
              Every decision and every change is written down here: {state?.audit.length ?? 0} entries so far. Turn off
              Simple view to read them.
            </p>
          ) : conn !== "ok" ? (
            <div className="mt-4"><Lines bars={["h-9", "h-9", "h-9"]} conn={conn} what="The audit trail is kept by the engine; it shows here once the engine answers." /></div>
          ) : state?.audit.length ? (
            <AuditTimeline rows={state.audit} />
          ) : (
            <p className="muted mt-3 text-sm">Nothing recorded yet. Each policy decision and change lands here, numbered, and can&rsquo;t be edited afterwards.</p>
          )}
        </section>
      </div>

      {/* ------------------------------------------------ the dock */}
      <div className="fixed inset-x-0 bottom-[max(1rem,env(safe-area-inset-bottom))] z-20 flex justify-center px-3">
        <div ref={dock} className="glass dock relative flex max-w-full gap-1 overflow-x-auto sm:gap-1.5" role="toolbar" aria-label="Demo moments">
          {MOMENTS.map((m) => {
            const blocked = m.needsLicence ? !active : m.id === "recertify" ? !licensed : false;
            const disabled = !!busy || blocked || conn !== "ok";
            return (
              <button key={m.id} data-moment={m.id} className="lq-btn shrink-0" data-tone={m.tone} disabled={disabled}
                aria-pressed={state?.last?.name === m.id} aria-busy={busy === m.id}
                title={conn !== "ok" ? "Waiting for the engine" : blocked ? (licensed ? "Licence revoked: Re-certify first" : "Earn a licence first") : `${m.hint}${m.n ? ` (key ${m.n})` : ""}`}
                aria-label={m.label} onClick={() => run(m.id)}>
                <span className="dock-num" aria-hidden>
                  {busy === m.id ? (
                    <svg className="spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 3a9 9 0 019 9" strokeLinecap="round" /></svg>
                  ) : m.n ?? (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"><path d="M20 12a8 8 0 11-2.3-5.6M20 4v4h-4" /></svg>
                  )}
                </span>
                <span className="sm:hidden lg:inline">{m.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </>
  );
}

// The suggested demo order. After Revoke the licence must be re-certified before Warn can show autonomy again.
const NEXT: Record<MomentId | "start", MomentId | null> = {
  start: "earn", earn: "act", act: "block", block: "revoke", revoke: "recertify", recertify: "federation",
  federation: "warning", warning: "self_revoke", self_revoke: null,
};

function nextMoment(last: MomentId | null, licensed: boolean): MomentId | null {
  const next = NEXT[last ?? "start"];
  return next && !licensed && MOMENTS.find((m) => m.id === next)?.needsLicence ? "recertify" : next;
}

function NextStep({ last, licensed, busy, running, run, armed, onReset }: {
  last: MomentId | null; licensed: boolean; busy: boolean; running: MomentId | null; run: (m: MomentId) => void;
  armed: boolean; onReset: () => void;
}) {
  const m = MOMENTS.find((x) => x.id === nextMoment(last, licensed));
  // The suggestion stays put while its moment runs, and the button says so.
  const shown = running ? MOMENTS.find((x) => x.id === running) ?? m : m;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-fg/10 px-5 py-4 sm:px-7">
      {armed ? (
        <p className="text-sm" role="status" style={{ color: "var(--amber)" }}>
          Press R again to reset the demo: licence, warnings, approvals and audit trail start over.
        </p>
      ) : shown ? (
        <>
          <p className="muted text-sm">
            {running ? "Running" : "Next in the demo"}: <b className="text-frost">{shown.n ? `${shown.n}. ` : ""}{shown.label}</b>. {shown.hint}.
          </p>
          <button className="lq-btn !min-h-[42px] text-sm" data-tone={shown.tone ?? "signal"} disabled={busy}
            aria-busy={running === shown.id} onClick={() => run(shown.id)}>
            {running === shown.id && (
              <svg className="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden><path d="M12 3a9 9 0 019 9" strokeLinecap="round" /></svg>
            )}
            {running === shown.id ? `Running ${shown.label}` : `Run ${shown.label}`}
          </button>
        </>
      ) : (
        <>
          <p className="muted text-sm">That is the whole demo. Reset it to run it again from the start, exactly as the first time.</p>
          <button className="lq-btn !min-h-[42px] text-sm" disabled={busy} onClick={onReset}>Reset demo</button>
        </>
      )}
    </div>
  );
}

// The opening statement beside the licence.
function Pitch({ status }: { status: string | null }) {
  const simple = useSimple();
  return (
    <div>
      <h1 className="max-w-[18ch] text-[clamp(2.1rem,4.4vw,3.6rem)] font-bold leading-[1.02] tracking-[-0.035em]">
        {simple
          ? "The AI fixes network faults on its own only after it proves it is rarely wrong."
          : "A network agent acts alone only while it can prove it’s right."}
      </h1>
      <p className="muted mt-5 max-w-[56ch] text-lg leading-relaxed">
        {simple
          ? "It is tested on past faults first. If it passes, it gets a licence that expires. Every action is checked against that licence and against fixed rules, and a person can take the licence away at any time."
          : "Its error rate on autonomous diagnoses is bounded by a statistical test, sealed into a signed licence that expires, and checked by policy on every tool call. Hard limits hold whatever the licence says."}
      </p>
      <Lifecycle status={status} />
    </div>
  );
}

// Stage mode's only chrome: where the demo has got to, and how to move on. The steps follow the suggested order;
// a step is done once it has run in this session, whatever order the presenter took.
const ORDER: MomentId[] = ["earn", "act", "block", "revoke", "recertify", "federation", "warning", "self_revoke"];

function StageBar({ last, seen, onExit }: { last: MomentId | null; seen: MomentId[]; onExit: () => void }) {
  return (
    <header className="flex items-center gap-5">
      <ol className="flex min-w-0 flex-1 gap-1.5" aria-label="Demo progress">
        {ORDER.map((id) => {
          const m = MOMENTS.find((x) => x.id === id)!;
          const s = id === last ? "now" : seen.includes(id) ? "done" : "todo";
          return (
            <li key={id} className="stage-step" data-s={s} data-tone={m.tone} aria-current={s === "now" ? "step" : undefined}>
              <span className="font-bold">
                {m.n ?? <svg aria-hidden className="inline h-[0.9em] w-[0.9em]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round"><path d="M20 12a8 8 0 11-2.3-5.6M20 4v4h-4" /></svg>}
              </span>{" "}
              <span className="truncate">{m.label}</span>
            </li>
          );
        })}
      </ol>
      <button type="button" className="lq-btn !min-h-[2.5rem] shrink-0 text-sm" onClick={onExit}>Leave stage</button>
    </header>
  );
}

function StageFoot({ next, busy, resetting, armed }: {
  next: MomentId | null; busy: MomentId | null; resetting: boolean; armed: boolean;
}) {
  const label = (id: MomentId) => MOMENTS.find((x) => x.id === id)!.label;
  return (
    <footer className="flex flex-wrap items-center justify-between gap-x-8 gap-y-1 text-sm" aria-live="polite">
      {armed ? (
        <span style={{ color: "var(--amber)" }}>Press R again to reset the demo.</span>
      ) : (
        <span className="muted">
          {resetting ? "Resetting the demo"
            : busy ? <>Running <b className="text-frost">{label(busy)}</b></>
            : next ? <>Next: <b className="text-frost">{label(next)}</b>. Press → or the clicker.</>
            : "That is the whole demo. Press R twice to start it over."}
        </span>
      )}
      <span className="faint">1 to 7 jump to a moment. R twice resets. S or Esc leaves stage.</span>
    </footer>
  );
}

// The licence's life, in order. The current stage follows the engine's licence status.
function Lifecycle({ status }: { status: string | null }) {
  const simple = useSimple();
  const steps = simple
    ? ["Tested on past faults", "Licence signed", "Every action checked", "Withdrawn when needed"]
    : ["Calibrate on held-back incidents", "Sign a licence that expires", "Enforce on every tool call", "Revoke, by a person or the evidence"];
  const reached = status === "revoked" ? 4 : status === "active" ? 3 : 0;
  return (
    <ol className="mt-8 grid max-w-[640px] grid-cols-2 gap-x-5 gap-y-4 sm:grid-cols-4" aria-label="Licence lifecycle">
      {steps.map((t, i) => {
        const done = i < reached;
        const color = !done ? "var(--frost-3)" : i === 3 ? "var(--ember)" : "var(--signal)";
        return (
          <li key={t} className="border-t-2 pt-2.5 text-sm leading-snug transition-colors duration-700" style={{ borderColor: color }}>
            <span className="block text-sm font-bold" style={{ color }}>{i + 1}</span>
            <span className={done ? "text-frost" : "faint"}>{t}</span>
          </li>
        );
      })}
    </ol>
  );
}

// Waiting on the engine: the shape of a decision, so the panel doesn't jump when it arrives.
function DecisionSkeleton() {
  return (
    <div className="late min-h-[415px] space-y-5 p-5 sm:p-7" role="status">
      <span className="sr-only">Connecting to the engine</span>
      <div className="skeleton h-8 w-2/5" />
      <div className="skeleton h-4 w-3/4" />
      <div className="flex justify-between pt-4">
        {[0, 1, 2, 3, 4].map((i) => <div key={i} className="skeleton h-[46px] w-[46px] !rounded-full" />)}
      </div>
      <div className="skeleton h-24 w-full !rounded-[14px]" />
    </div>
  );
}

// The engine didn't answer. Say what that means for the demo, how to start it, and keep checking on our own.
function EngineDown({ checking, onRetry }: { checking: boolean; onRetry: () => void }) {
  return (
    <div className="reveal p-5 sm:p-7" role="alert">
      <div className="flex items-start gap-4">
        <span className="node shrink-0" data-s="deny" aria-hidden>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 7V3m6 4V3M7 7h10v4a5 5 0 01-10 0V7zm5 9v5M4 4l16 16" />
          </svg>
        </span>
        <div className="min-w-0">
          <h2 className="text-2xl font-semibold tracking-tight">The engine isn&rsquo;t answering</h2>
          <p className="muted mt-2 max-w-[60ch] leading-relaxed">
            Every licence, decision and audit entry on this page comes from the engine API on port 8000; the browser computes
            none of it. Until the engine answers, nothing is shown as licensed and no moment can run.
          </p>
          <p className="mt-4 text-sm font-semibold">Start it from the autonomy-license folder:</p>
          <pre className="glass-card mt-2 overflow-x-auto px-4 py-3 font-[family-name:var(--font-serial)] text-sm text-frost">python -m uvicorn api.server:app --port 8000</pre>
          <div className="mt-5 flex flex-wrap items-center gap-3">
            <button type="button" className="lq-btn !min-h-[42px] text-sm" data-tone="signal" disabled={checking} onClick={onRetry}>
              {checking && <svg className="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden><path d="M12 3a9 9 0 019 9" strokeLinecap="round" /></svg>}
              {checking ? "Checking" : "Try again"}
            </button>
            <span className="faint text-sm">The console checks again every few seconds and comes back on its own.</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// Placeholders while the engine loads, one bar per block of the content to come and the same height, so nothing
// moves when it arrives; a plain note while it's down.
function Lines({ bars, conn, what }: { bars: string[]; conn: "loading" | "ok" | "down"; what?: string }) {
  if (conn === "down") return <p className="faint mt-2 text-sm">{what ?? "Shown once the engine answers."}</p>;
  return (
    <div className="late space-y-2" aria-hidden>
      {bars.map((b, i) => <div key={i} className={`skeleton w-full !rounded-[14px] ${b}`} />)}
    </div>
  );
}

// An error from the engine about one moment: what it said, and a way to clear it.
function ErrorBar({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return (
    <div role="alert" className="glass reveal flex items-center gap-3 py-2 pl-5 pr-2 text-sm" style={{ borderRadius: 999 }}>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--ember)" strokeWidth="2.2" strokeLinecap="round" aria-hidden className="shrink-0">
        <path d="M12 8v5m0 3.5v.5M10.3 3.9L2.4 17.5A2 2 0 004.1 20.5h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
      </svg>
      <span className="min-w-0 flex-1"><b style={{ color: "var(--ember)" }}>The engine refused:</b> <span className="muted">{message}</span></span>
      <button type="button" className="lq-btn !min-h-[36px] !px-3 text-sm" onClick={onDismiss}>Dismiss</button>
    </div>
  );
}

// Why a change is waiting for a person. The engine's reason says why the agent couldn't act alone; read raw,
// "denied: …" looks as if an engineer had already said no. The raw reason stays in the tooltip and the audit trail.
function approvalWhy(reason: string) {
  if (reason.startsWith("denied:")) return "Policy refused the agent, so a person decides.";
  if (reason === "below licensed threshold") return "Confidence is below the licensed threshold.";
  if (reason.startsWith("catalogue class")) return "This kind of fix always needs a person.";
  return reason;
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="px-3 py-2.5">
      <dt className="faint text-xs">{k}</dt>
      <dd className="mt-0.5 font-semibold tracking-tight">{v}</dd>
    </div>
  );
}
