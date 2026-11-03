import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import Backdrop from "@/components/Backdrop";
import { ArchitectureDiagram, DecisionDiagram, FederationDiagram, Figure, LifecycleFlow } from "@/components/Diagrams";
import SimpleIntro from "@/components/SimpleIntro";
import TopBar from "@/components/TopBar";

export const metadata: Metadata = {
  title: "Help · Autonomy License",
  description: "First run, how the system works in diagrams, the demo script, what every number means, and how to run it on AWS.",
};

const SECTIONS = [
  ["what", "What this is"],
  ["simple", "The simple version"],
  ["example", "One example, start to end"],
  ["first", "Your first run"],
  ["how", "How it works"],
  ["console", "Using the console"],
  ["demo", "Demo script"],
  ["read", "Reading a decision"],
  ["terms", "Terms"],
  ["limits", "What we can claim"],
  ["aws", "Running it on AWS"],
  ["plan", "Build status"],
  ["trouble", "If something looks wrong"],
] as const;

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="glass scroll-mt-6 p-5 sm:p-7">
      <h2 className="text-2xl font-semibold tracking-[-0.02em]">{title}</h2>
      <div className="help-body mt-4 space-y-4">{children}</div>
    </section>
  );
}

function Code({ children }: { children: string }) {
  return (
    <pre className="glass-card overflow-x-auto px-4 py-3 text-sm leading-relaxed text-frost">
      <code>{children}</code>
    </pre>
  );
}

const SIMPLE: [string, string][] = [
  ["It takes a test", "The agent is tested on past faults, with the pass mark fixed in advance. To pass, its solo diagnoses must be wrong at most 5% of the time. Its result: at most 1.19%."],
  ["It gets a licence", "Passing earns a signed permit. It expires, names the exact model, and lists the faults and actions it covers."],
  ["Every action is checked", "Before each change, a separate checker works out the facts itself: is the licence valid, is the agent confident enough, how many cells would change? Anything the agent says about itself is ignored."],
  ["Some rules never bend", "No change may touch more than 3 cells, even with a valid licence. Some actions are never taken alone."],
  ["People handle the rest", "If a change falls outside the licence, it is refused and queued for an engineer to approve or deny."],
  ["The licence can be taken away", "Withdraw it, and the agent's next solo change is refused. To act alone again, it has to earn a new licence."],
  ["Everything leaves a record", "Each step is saved under one run id, so anyone can check what happened instead of taking our word for it."],
];

const DATA_GROUPS: [string, string, string][] = [
  ["Pilot", "60", "An early check of the model"],
  ["Calibration", "450", "The test that earns the licence"],
  ["Held-out", "308", "A separate final check, and the live examples"],
];

const ALLOWED_TIMELINE: [string, string][] = [
  ["00:01:50.1", "The agent asks to apply set_handover_params to 2 cells."],
  ["00:01:54.8", "The Gateway check ignores the agent's claims and writes its own facts: 2 cells, licence valid, score valid. Cedar policy then allows the call."],
  ["00:01:58.9", "The tool checks everything again and records the call before acting."],
  ["00:01:59.2", "The change is applied to the simulated network."],
  ["00:01:59.4", "The agent gets its reply."],
];

const PROOF: [string, string][] = [
  ["Declared first", "The target and the items go to S3 before each run starts."],
  ["Records", "Every step is saved in DynamoDB and CloudWatch under one run id."],
  ["Live test", "tools/show_record.py shows any item a judge names, using read-only calls."],
  ["Rebuild", "tools/rebuild.py recalculates every result from the files, with no AWS access."],
];

const DEMO: { n: string; name: string; press: string; see: string; say: string }[] = [
  {
    n: "1", name: "Earn",
    press: "Press Earn (key 1).",
    see: "The licence is issued and its seal stamps in: the ring is the certified error bound against the 5% budget. The chart shows each threshold tested from strict to loose against the 5% line. Teal points passed; a coral point, if there is one, is where testing stopped. The last teal point is the licensed threshold.",
    say: "The agent doesn't get autonomy by promising. It earns it on incidents it has never seen, with a test fixed before we looked at the results, and the result is a signed licence that expires.",
  },
  {
    n: "2", name: "Act",
    press: "Press Act (key 2).",
    see: "A confident diagnosis passes every node and the simulated cells change. A doubtful one stops at the agent and is queued for an engineer, who approves and executes it.",
    say: "Above the licensed threshold the agent fixes it alone. Below it, a person approves the exact change. Same agent, same tools, and the evidence decides who acts.",
  },
  {
    n: "3", name: "Block",
    press: "Press Block (key 3).",
    see: "The agent asks to change 5 cells and claims it's 2. The interceptor counts the real cells, Cedar policy F1 denies it, and even an engineer with a valid approval is denied. Network changes: 0.",
    say: "Some rules don't bend to statistics. No one changes more than 3 cells at once, and the agent can't lie its way past the count, because the server computes it.",
  },
  {
    n: "4", name: "Revoke",
    press: "Press Revoke (key 4).",
    see: "A REVOKED stamp lands on the licence and the background drains. The next confident diagnosis is denied, because no policy permits it any more, and it goes to an engineer.",
    say: "One action takes autonomy away, and it takes effect on the very next call. Control goes back to humans.",
  },
  {
    n: "", name: "Re-certify",
    press: "Press Re-certify.",
    see: "A new calibration round issues a new licence. The revoked one is never switched back on.",
    say: "Getting autonomy back means earning it again.",
  },
  {
    n: "5", name: "Federate",
    press: "Press Federate (key 5).",
    see: "Each operator alone, often with too little evidence. Then the pooled result from masked sums of their counts, and a check that the masked sum equals the direct sum.",
    say: "Smaller operators can't prove much alone. Pooling counts, not data, gives them a licence together. It's a federation-level licence, not a promise for each operator.",
  },
  {
    n: "6", name: "Warn",
    press: "Press Warn (key 6). Needs an active licence, so Re-certify first if you revoked.",
    see: "Operator B hits a hard rule and sends a signed warning for that category. Operator A stops acting alone in that category, but still acts alone in others.",
    say: "Operators share what went wrong, not their data, and the warning narrows autonomy only where the risk is.",
  },
  {
    n: "7", name: "Self-revoke",
    press: "Press Self-revoke (key 7).",
    see: "The proven licence is checked against real held-out outcomes and stays active. A fresh licence then meets injected drift from its first action; the evidence crosses its bar, the licence revokes itself, and the next call goes to an engineer.",
    say: "Nobody has to notice the model going wrong. Every outcome is checked, and a licence that stops earning its keep withdraws itself, with a bounded chance of a false alarm however often we check.",
  },
];

const FIRST_RUN: [string, ReactNode][] = [
  ["Start the engine", <>It runs every statistic and policy check: <b>python -m uvicorn api.server:app --port 8000</b>.</>],
  ["Start the web app", <>In <b>web</b>, run <b>npm run dev</b> and open <b>localhost:3000</b>.</>],
  ["Earn a licence", <>Press <b>1</b>. The test runs on held-back faults and, if the bound fits the budget, the licence is signed.</>],
  ["Follow the next step", <>The bar under each result names the next moment. Press it, or its number key, through all seven.</>],
  ["Read what happened", <>Each result shows the path the call took and which policy decided. The audit trail at the bottom records everything.</>],
  ["Switch to Simple view", <>Top right. Every screen is explained in plain words, for an audience that doesn&apos;t know the statistics.</>],
  ["Start over", <>Press R twice, or Reset demo at the end. It clears the licence, warnings, approvals, audit and the simulated network.</>],
];

const POLICIES: [string, string][] = [
  ["P1", "The agent and engineers may read an incident and ask for approval."],
  ["P2k1 to P2k4", "The agent may act alone in that category, only with an active licence, a server-checked score at or above the threshold, at most 3 cells and an allowed action."],
  ["P3", "An engineer may execute a change that was approved for that exact incident, action and cells."],
  ["F1", "Hard rule: never more than 3 cells, for anyone. The cell count is computed by the server."],
  ["F1m", "Hard rule: a change without a server-computed cell count is refused, so a bypassed interceptor fails closed."],
  ["F2", "Hard rule: some actions are never taken autonomously."],
  ["F3k1 to F3k4", "A category with an active warning is not autonomous."],
  ["No policy listed", "Nothing permitted the call, so the default applies: deny. This is what a revoked licence looks like."],
];

const TERMS: [string, string][] = [
  ["α (alpha)", "The error budget: the most autonomous diagnoses we accept being wrong. Pre-registered at 5%."],
  ["δ (delta)", "How often the test itself may be fooled by bad luck. 10%, so the bound holds with 90% confidence."],
  ["λ̂ (threshold)", "The model confidence above which the agent may act alone. Chosen by the test, then sealed in the licence."],
  ["U (bound)", "The upper confidence bound on the error rate of autonomous diagnoses. Licensed only if U is at most α."],
  ["n / k", "How many calibration incidents were above the threshold, and how many of those the model got wrong."],
  ["Fixed sequence", "Thresholds are tested in a fixed order from strict to loose, and testing stops at the first failure. That is what makes the bound valid without correcting for many tests."],
  ["Held-out", "Incidents kept aside until the end and never used to choose anything. They show what happens next, not what we tuned."],
  ["PREREG", "The pre-registration file: grid, α, δ and data split hashes, fixed and hashed before calibration."],
  ["Licence", "An ES256-signed JWT with the threshold, the evidence, its scope and an expiry. Checked against a live registry on every call."],
  ["Interceptor", "Runs before policy. Drops any trust field the agent sends and writes the server's own cell count, category, score check and licence check."],
  ["Tool re-check", "The tool itself re-verifies everything before touching the network, in case anything upstream was wrong."],
];

export default function HelpPage() {
  return (
    <>
      <Backdrop mood="idle" pulse={0} />
      <div className="mx-auto max-w-[1240px] px-4 pb-24 pt-5 sm:px-6">
        <TopBar active="help" />

        <header className="mt-10 max-w-3xl">
          <h1 className="text-[clamp(2rem,4vw,3rem)] font-semibold leading-[1.05] tracking-[-0.03em]">Help and demo guide</h1>
          <p className="muted mt-3 text-lg leading-relaxed">
            Your first run, how the system works in diagrams, the seven-moment demo, what every number means, and how to run it on
            AWS.
          </p>
        </header>

        <SimpleIntro />

        <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-[230px_1fr]">
          <nav aria-label="On this page" className="lg:sticky lg:top-6 lg:self-start">
            <ol className="glass flex gap-1 overflow-x-auto p-2 lg:flex-col lg:overflow-visible" style={{ borderRadius: 26 }}>
              {SECTIONS.map(([id, label]) => (
                <li key={id} className="shrink-0">
                  <a href={`#${id}`} className="block rounded-full px-4 py-2 text-sm text-[var(--frost-2)] transition-colors hover:bg-fg/10 hover:text-frost focus-visible:outline-2 focus-visible:outline-[var(--signal)]">
                    {label}
                  </a>
                </li>
              ))}
            </ol>
          </nav>

          <div className="min-w-0 space-y-6">
            <Section id="what" title="What this is">
              <p>
                A network AI agent diagnoses the root cause of 5G faults. It may fix a fault on its own only when a statistical
                test shows that its autonomous diagnoses are wrong at most 5% of the time, with 90% confidence. That evidence
                becomes a signed licence that expires. Policy checks the licence on every tool call, hard rules hold whatever
                the licence says, and revoking it hands control back to people.
              </p>
              <p>
                Our entry for the Breaking Barriers Hackathon at FYUZ 2026. The design follows build spec v1.2.1.
              </p>
            </Section>

            <Section id="simple" title="The simple version">
              <p>Think of a new driver: pass a test, get a licence, follow the rules of the road, and lose the licence if needed.</p>
              <ol className="space-y-3">
                {SIMPLE.map(([t, d], i) => (
                  <li key={t} className="glass-card flex gap-4 p-4">
                    <span className="dock-num shrink-0" style={{ ["--tint" as string]: "var(--signal-rgb)" }}>{i + 1}</span>
                    <div className="min-w-0">
                      <b>{t}</b>
                      <div className="muted mt-1 text-body leading-relaxed">{d}</div>
                    </div>
                  </li>
                ))}
              </ol>
              <p className="faint text-sm">The network here is simulated, so no real cells change.</p>
            </Section>

            <Section id="example" title="One example, start to end">
              <p>
                Real incidents and numbers from our declared runs in the team AWS account, 2 to 3 November 2026 (UTC). The incident
                text itself stays out of this page, because the dataset is gated.
              </p>

              <h3 className="text-lg font-semibold">1. The data</h3>
              <p>
                We use the TeleLogs dataset from Hugging Face, which describes 5G faults along with the correct cause of each.
                After removing rows that also appear in training and rows with more than one cause, 818 incidents remain.
              </p>
              <div className="glass-card overflow-x-auto">
                <table className="w-full text-left text-body">
                  <caption className="sr-only">How the 818 incidents are split</caption>
                  <thead><tr className="faint border-b border-fg/10"><th className="px-4 py-2.5 font-medium">Group</th><th className="px-4 py-2.5 font-medium">Incidents</th><th className="px-4 py-2.5 font-medium">Used for</th></tr></thead>
                  <tbody>
                    {DATA_GROUPS.map(([g, n, u]) => (
                      <tr key={g} className="border-b border-fg/5 last:border-0 align-top">
                        <td className="px-4 py-2.5 font-semibold">{g}</td>
                        <td className="px-4 py-2.5">{n}</td>
                        <td className="muted px-4 py-2.5">{u}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3 className="text-lg font-semibold">2. The model diagnoses an incident</h3>
              <p>
                The model att/OTel-LLM-8.3B-Classification reads incident <b>TL-bc9c026237c1</b> and answers <b>C6</b>, &ldquo;Frequent
                handovers degrade performance&rdquo;, with a confidence of <b>0.9059</b>.
              </p>

              <h3 className="text-lg font-semibold">3. The test and the licence</h3>
              <p>
                The rule is that the agent acts alone only at a confidence of 0.70 or more. On the calibration incidents, 446 passed
                that bar and 2 of those diagnoses were wrong. Statistics turn that into a limit: the real error rate is at most
                <b> 1.19%</b>, with 90% confidence. The target was 5% or less, so it passes, and AWS KMS signs the licence.
              </p>

              <h3 className="text-lg font-semibold">4. A change that is allowed</h3>
              <p>Incident TL-bc9c026237c1 is covered by the licence, so no person has to approve the change.</p>
              <div className="glass-card overflow-x-auto">
                <table className="w-full text-left text-body">
                  <caption className="sr-only">The steps of one allowed change, with UTC times</caption>
                  <thead><tr className="faint border-b border-fg/10"><th className="px-4 py-2.5 font-medium">Time (UTC)</th><th className="px-4 py-2.5 font-medium">What happened</th></tr></thead>
                  <tbody>
                    {ALLOWED_TIMELINE.map(([t, d]) => (
                      <tr key={t} className="border-b border-fg/5 last:border-0 align-top">
                        <td className="whitespace-nowrap px-4 py-2.5 font-semibold">{t}</td>
                        <td className="muted px-4 py-2.5">{d}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3 className="text-lg font-semibold">5. A change that is refused</h3>
              <p>
                Incident <b>TL-e8b0f757fe2c</b> also has a high score, 0.9081, and a valid licence, but the change is too big. The
                Gateway check throws away the agent&apos;s own cell count (the record shows <b>dropped: cell_count</b>) and counts
                <b> 6 cells</b> itself. The limit is 3, so Cedar refuses it and nothing changes. High confidence is not enough, and
                the agent cannot lie its way past the limit.
              </p>

              <h3 className="text-lg font-semibold">6. Taking the licence away</h3>
              <p>
                In the pause run, the licence and the models are withdrawn. The agent then tries ordinary 2-cell changes, such as
                <b> TL-91bff37beb66</b>. All 10 are refused, and so is a call to the withdrawn model. Control goes back to people.
              </p>

              <h3 className="text-lg font-semibold">7. When a person decides</h3>
              <p>
                For incident <b>TL-db60e2b54dfa</b>, the proposed action is rebalance_scheduler, which the licence does not cover. The
                change is refused, the specialist model writes a note for the engineer, and the request waits in a queue for a person
                to approve or deny.
              </p>

              <h3 className="text-lg font-semibold">8. Proving it</h3>
              <dl className="grid gap-x-8 gap-y-5 sm:grid-cols-2">
                {PROOF.map(([k, v]) => (
                  <div key={k} className="border-t border-fg/10 pt-3">
                    <dt className="font-semibold">{k}</dt>
                    <dd className="muted mt-1 text-body leading-relaxed">{v}</dd>
                  </div>
                ))}
              </dl>

              <p>
                <b>What this does not prove.</b> The network is simulated, and &ldquo;resolved&rdquo; comes from the dataset&apos;s correct
                answer. The 1.19% covers wrong diagnoses in this filtered, single-cause data, not whether an action is safe; the hard
                rules and the tool&apos;s re-check handle that. The model was trained on TeleLogs, so its accuracy says little about
                other networks.
              </p>
            </Section>

            <Section id="first" title="Your first run">
              <p>About five minutes, all local, no AWS needed. From the <b>autonomy-license</b> folder:</p>
              <ol className="space-y-3">
                {FIRST_RUN.map(([t, d], i) => (
                  <li key={t} className="glass-card flex gap-4 p-4">
                    <span className="dock-num shrink-0" style={{ ["--tint" as string]: "var(--signal-rgb)" }}>{i + 1}</span>
                    <div className="min-w-0">
                      <b>{t}</b>
                      <div className="muted mt-1 text-body leading-relaxed">{d}</div>
                    </div>
                  </li>
                ))}
              </ol>
              <p>The commands, in two terminals:</p>
              <Code>{`pip install -r requirements.txt
python -m uvicorn api.server:app --port 8000`}</Code>
              <Code>{`cd web
npm install
npm run dev        # open http://localhost:3000`}</Code>
              <p>
                The web app only displays results: every number comes from the Python engine through <b>/api</b>. The older
                Streamlit console still works with <b>streamlit run console/app.py</b>, and <b>python scripts/demo.py</b> runs
                all seven moments in a terminal. <b>pytest</b> runs the release checklist.
              </p>
            </Section>

            <Section id="how" title="How it works">
              <p>
                Two halves. <b>Prove</b> runs once: the model is scored on faults it has never seen, a pre-registered test turns
                that evidence into a threshold, and AWS KMS signs it as a licence. <b>Enforce</b> runs on every tool call: the
                server, never the agent, supplies the facts, and Cedar policy decides.
              </p>
              <Figure minWidth={760} title="Architecture"
                caption={<>Top: proving, once. Middle: the path every tool call takes through AgentCore Gateway. Bottom: people and shared state. Nothing the agent sends about itself is believed.</>}>
                <ArchitectureDiagram />
              </Figure>
              <div>
                <b className="mb-3 block text-lg">The licence&apos;s life</b>
                <LifecycleFlow />
              </div>
              <Figure minWidth={560} title="How one tool call is decided"
                caption={<>The agent acts alone only when all three checks pass. A failed licence or warning check hands the call to an engineer; the 3-cell rule stops everyone.</>}>
                <DecisionDiagram />
              </Figure>
              <Figure minWidth={640} title="Federation"
                caption={<>Small operators can&apos;t prove much alone. They pool counts, not incidents, and earn one licence for the federation, not a promise for each of them.</>}>
                <FederationDiagram />
              </Figure>
            </Section>

            <Section id="console" title="Using the console">
              <ul className="list">
                <li><b>The licence.</b> An operating permit for the agent. The seal&apos;s ring is the certified error bound as a share of the 5% budget. A dashed outline before Earn; a REVOKED stamp when withdrawn.</li>
                <li><b>On the licence.</b> Threshold, the evidence behind it, when it expires and which categories it covers; a category under a warning is struck through.</li>
                <li><b>Lifecycle and live proof.</b> Beside the licence, where it is in its life. Below it, what the deployed AWS Gateway did on its last live run, read from the evidence files.</li>
                <li><b>Dock at the bottom.</b> The demo moments in order. Buttons that need a licence stay disabled until you press Earn. Keys 1 to 7 run them too.</li>
                <li><b>Decision panel.</b> What the last moment did, incident by incident, with the enforcement path and the policies that decided it. Under each refused call, the facts the interceptor computed (next to anything the agent claimed) and the Cedar text that fired, quoted from the deployed policies. The bar at its foot suggests the next moment.</li>
                <li><b>Waiting for an engineer.</b> Approval requests the agent raised. They are single-use, expire in 10 minutes and are bound to the exact incident, action and cells.</li>
                <li><b>Try another error budget.</b> Shows what 2% or 10% would have allowed. Only 5% was pre-registered, so only 5% is certified.</li>
                <li><b>Audit trail.</b> Every policy decision and change, append-only, with incident ids hashed.</li>
              </ul>
            </Section>

            <Section id="demo" title="Demo script">
              <p>A few minutes end to end. Run the moments in this order. Each step says what to press, what to point at and one thing to say.</p>
              <ol className="divide-y divide-[rgb(var(--line-rgb)/0.14)]">
                {DEMO.map((d) => (
                  <li key={d.name} className="grid gap-3 py-5 first:pt-1 last:pb-1 sm:grid-cols-[120px_1fr]">
                    <div className="flex items-center gap-3 sm:block">
                      <span className="dock-num" style={{ ["--tint" as string]: "var(--signal-rgb)" }}>{d.n || "↺"}</span>
                      <b className="text-lg sm:mt-2 sm:block">{d.name}</b>
                    </div>
                    <dl className="grid max-w-[58ch] gap-2 text-body leading-relaxed">
                      <div><dt className="faint inline">Do </dt><dd className="inline">{d.press}</dd></div>
                      <div><dt className="faint inline">Point at </dt><dd className="inline muted">{d.see}</dd></div>
                      <div><dt className="faint inline">Say </dt><dd className="inline">&ldquo;{d.say}&rdquo;</dd></div>
                    </dl>
                  </li>
                ))}
              </ol>
              <p className="faint text-sm">Reset before you present, and between runs: press R twice, or Reset demo at the end. It is
                the same as restarting the API: licence, warnings, approvals, audit trail and simulator all start over. Pressing Earn
                again only issues a fresh licence; Operator B&rsquo;s warning stays in force for up to two hours, so without a reset
                Act&rsquo;s confident diagnosis in that category would go to an engineer.</p>
              <p className="faint text-sm">On a projector, press S (or the screen icon in the top bar) for stage mode: full screen, no
                controls, type sized to the screen, one moment at a time. The right arrow, Page Down (what a presenter clicker sends)
                or Space runs the next moment, 1 to 7 jump, R twice resets, and Esc leaves.</p>
            </Section>

            <Section id="read" title="Reading a decision">
              <p>Every call travels the same path. Each node lights up to show how far it got:</p>
              <ul className="list">
                <li><b>Agent</b> picks the catalogue action for its diagnosis, or asks for approval if it isn&apos;t confident enough.</li>
                <li><b>Interceptor</b> overwrites cell count, category, score check and licence check with server values.</li>
                <li><b>Cedar policy</b> permits or forbids. A forbid always wins and the default is deny.</li>
                <li><b>Tool re-check</b> verifies everything again before any change.</li>
                <li><b>Network</b> is a simulator. Its before and after values are shown when a change is applied.</li>
              </ul>
              <div className="flex flex-wrap gap-2">
                <span className="pill" data-tone="signal">Teal: allowed</span>
                <span className="pill" data-tone="ember">Coral: denied</span>
                <span className="pill" data-tone="amber">Amber: handed to an engineer</span>
              </div>
              <div className="glass-card overflow-hidden">
                <table className="w-full text-left text-body">
                  <caption className="sr-only">Policy identifiers</caption>
                  <thead><tr className="faint border-b border-fg/10"><th className="px-4 py-2.5 font-medium">Policy</th><th className="px-4 py-2.5 font-medium">Meaning</th></tr></thead>
                  <tbody>
                    {POLICIES.map(([k, v]) => (
                      <tr key={k} className="border-b border-fg/5 last:border-0 align-top">
                        <td className="whitespace-nowrap px-4 py-2.5 font-semibold">{k}</td>
                        <td className="muted px-4 py-2.5">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>

            <Section id="terms" title="Terms">
              <dl className="grid gap-x-8 gap-y-5 sm:grid-cols-2">
                {TERMS.map(([k, v]) => (
                  <div key={k} className="border-t border-fg/10 pt-3">
                    <dt className="font-semibold">{k}</dt>
                    <dd className="muted mt-1 text-body leading-relaxed">{v}</dd>
                  </div>
                ))}
              </dl>
            </Section>

            <Section id="limits" title="What we can claim">
              <p>Say these on stage. They are true of the system, and judges will ask.</p>
              <ul className="list">
                <li>The bound covers <b>wrong autonomous diagnoses</b> for the filtered single-cause population. It says nothing about whether an action is safe; the hard rules do that.</li>
                <li>The network is simulated. Whether a fault is &ldquo;resolved&rdquo; is decided from the ground-truth label, so it shows enforcement, not remediation quality.</li>
                <li>A pooled licence is a federation-level result. Per-operator figures are measurements, not guarantees.</li>
                <li>Masking assumes an honest-but-curious aggregator, no collusion, no dropouts and honest counts. There is no differential privacy.</li>
                <li>The console runs on <b>real TeleLogs test incidents</b>, scored by a classifier that was fine-tuned on TeleLogs; we use only its test split. The top bar says which data is loaded.</li>
                <li>Moment 7&apos;s drift is <b>synthetic</b>: injected on a fresh licence using stand-in incidents. Real outcomes are never altered.</li>
              </ul>
            </Section>

            <Section id="aws" title="Running it on AWS">
              <p>
                The stack is deployed in the team account in <b>us-east-2</b>: Cognito, AgentCore Gateway and Policy, three Lambdas,
                six DynamoDB tables and a KMS signing key. All of it is pay-per-request; the KMS key costs about $1 a month even when idle.
              </p>
              <ol className="list">
                <li><b>Sign in</b> to AWS on the build machine.</li>
                <li><b>Resume</b> the stack. While paused, every Lambda is throttled to zero, so nothing can run or bill.</li>
                <li><b>Rebuild the licence</b>, which lasts hours on purpose, then package and deploy it.</li>
                <li><b>Prove it</b>: the smoke test makes one allowed and one denied call; the attack run tries seven ways to cheat.</li>
                <li><b>Pause</b> again when you are done, and sign out.</li>
              </ol>
              <Code>{`python -m aws.infra.pause resume
python -m aws.infra.stub_bundle --out dist/bundle --data state/data --kms-key alias/al-licence-issuer
python -m aws.infra.package --bundle dist/bundle --out dist/netops_lambda.zip
python -m aws.infra.deploy apply
python -m aws.infra.smoke
python -m aws.infra.attacks_live
python -m aws.infra.pause pause`}</Code>
              <p className="faint text-sm">These are for a quick check. The strip in the console reads the declared runs from python -m aws.infra.judged_run (judging.json and evidence/), or the newest rehearsal, labelled as one.</p>
            </Section>

            <Section id="plan" title="Build status">
              <p>Strict order: nothing later starts until the item before it passes. These are the first results, from 31 October 2026 in a personal account. The reported results are the declared team-account runs in judging.json.</p>
              <ol className="space-y-3">
                <Plan p="P0" title="1. Real AgentCore Gateway smoke test" status="Done live"
                  tone="signal" detail="Deployed in ENFORCE mode: a 2-cell change is allowed, a 6-cell change is denied by Cedar F1." />
                <Plan p="P0" title="2. Real TeleLogs data and classifier scores" status="Done"
                  tone="signal" detail="818 single-cause test incidents scored on a SageMaker GPU. Licensed threshold 0.70 on 446 cases with 2 wrong: a 1.19% bound against a 5% budget." />
                <Plan p="P0" title="3. Real licence on the AWS path, KMS signing" status="Done live"
                  tone="signal" detail="AWS KMS signs the licence; DynamoDB holds licence status and warnings, so a revoke reaches every Lambda." />
                <Plan p="P1" title="Federation and warnings" status="Works, local and DynamoDB"
                  tone="signal" detail="Masked count sums and signed warnings, on real scores." />
                <Plan p="P2" title="Attack scenarios" status="Done"
                  tone="signal" detail="8 of 8 blocked locally; 6 of 6 blocked as real calls to the deployed Gateway. The planner agent and IoT transport are not being built." />
              </ol>
              <p className="faint text-sm">Not building: offline edge authority, a second diagnosis model, or control of a real network.</p>
            </Section>

            <Section id="trouble" title="If something looks wrong">
              <ul className="list">
                <li><b>&ldquo;Can&rsquo;t reach the engine API&rdquo;.</b> Start it with <b>python -m uvicorn api.server:app --port 8000</b> and reload.</li>
                <li><b>Most buttons are disabled.</b> There is no licence yet. Press Earn.</li>
                <li><b>Warn is disabled after Revoke.</b> That is correct: press Re-certify first.</li>
                <li><b>Approvals pile up.</b> Several moments raise approval requests that nobody executes during the demo, and some could never pass the 3-cell rule anyway. Resetting the demo (R twice) clears them.</li>
                <li><b>The numbers differ from the slides.</b> Check the data badge in the top bar: TeleLogs data or Synthetic data.</li>
                <li><b>Live calls to AWS fail.</b> The stack is probably paused, or the licence has expired. See Running it on AWS.</li>
              </ul>
              <p><Link href="/" className="lq-btn !min-h-[42px] text-sm" data-tone="signal">Open the console</Link></p>
            </Section>
          </div>
        </div>
      </div>
    </>
  );
}

function Plan({ p, title, status, tone, detail }: { p: string; title: string; status: string; tone: string; detail: string }) {
  return (
    <li className="glass-card p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="pill">{p}</span>
        <b className="mr-auto">{title}</b>
        <span className="pill" data-tone={tone || undefined}>{status}</span>
      </div>
      <p className="muted mt-2 text-body leading-relaxed">{detail}</p>
    </li>
  );
}
