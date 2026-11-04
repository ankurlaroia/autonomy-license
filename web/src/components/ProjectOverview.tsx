"use client";

import { useState } from "react";

import { useSimple } from "@/lib/simple";

type Mode = "simple" | "detailed";
type Part = { title: string; simple: string; detailed: string };

const PARTS: Part[] = [
  {
    title: "The problem",
    simple: "AI could fix many phone network faults in seconds. But network operators won't let it change a live network on its own, because nobody can prove when it's safe to trust.",
    detailed: "\"Usually right\" isn't something a risk owner can sign, check or withdraw. And an agent that vouches for itself can cheat, so its own claims about its confidence, the fault category, the cell count or its licence can't be trusted.",
  },
  {
    title: "Our idea",
    simple: "The AI has to earn a permit, like a driving licence. It passes a test first. The permit is signed, it expires, and it can be taken away.",
    detailed: "Autonomy License is a signed, expiring permission tied to statistical evidence. It names the exact model and threshold, and lists the fault categories and actions it covers. Above the licensed threshold the agent acts alone. Below it, an engineer approves the exact change.",
  },
  {
    title: "How it earns the permit",
    simple: "The AI is tested on past faults, with the pass mark set in advance: its solo diagnoses can be wrong at most 5% of the time. Its result was at most 1.19%.",
    detailed: "Calibration runs on a frozen set of 450 filtered, single-cause TeleLogs incidents, with a 5% risk target. The agent made 446 solo diagnoses and got 2 wrong, which gives an upper bound of 1.19% at 90% confidence. AWS KMS signs the licence only after the evidence passes, and it lasts four hours.",
  },
  {
    title: "How it's kept in check",
    simple: "Every action goes through a separate checker that works out the facts for itself and ignores what the AI says about itself. Some rules never bend: no change can touch more than 3 cells.",
    detailed: "Every call passes through the AgentCore Gateway. An interceptor drops the agent's trust fields and writes the server's own cell count, category, score check and licence check. A Cedar policy then permits or forbids the call, and the tool checks everything again before acting. The agent never supplies its own score, category, cell count or licence validity.",
  },
  {
    title: "What we proved",
    simple: "We ran eight declared tests on AWS and all eight passed. Big changes were refused, attacks were blocked, and once the permit was withdrawn, the AI's next attempts were refused too.",
    detailed: "Across eight declared runs: 10 of 10 licensed changes applied, 10 of 10 oversized changes refused, 7 of 7 attacks blocked, and 11 of 11 calls refused after the licence and models were withdrawn. Each target is declared before its run, and every step is recorded in DynamoDB and CloudWatch under one run id. tools/rebuild.py recalculates the results from the evidence with no AWS access.",
  },
  {
    title: "What it doesn't prove",
    simple: "The test covers diagnoses, not whether every action is safe. The changes went to a simulated network, not a real one, and any other network would have to earn its own permit.",
    detailed: "The bound covers wrong autonomous diagnoses for the filtered single-cause population, not action safety. \"Resolved\" comes from the simulator's ground truth. The classifier was fine-tuned on TeleLogs, so its accuracy says little about other networks. Pooled licences are federation-level, not per-operator. This public console runs the engine on a simulated network and doesn't read the AWS records from the declared runs.",
  },
];

export default function ProjectOverview() {
  // Starts in simple words for a first-time visitor, and follows the Simple view switch in the top bar when it's used.
  const globalSimple = useSimple();
  const [mode, setMode] = useState<Mode>("simple");
  const [seen, setSeen] = useState(globalSimple);
  if (globalSimple !== seen) {
    setSeen(globalSimple);
    setMode(globalSimple ? "simple" : "detailed");
  }

  return (
    <section aria-labelledby="overview-title" className="glass mt-8 p-5 sm:p-7">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h2 id="overview-title" className="text-2xl font-semibold tracking-[-0.02em]">About the project</h2>
        <div role="radiogroup" aria-label="Level of detail" className="flex gap-1 rounded-full bg-sink p-1">
          {(["simple", "detailed"] as const).map((m) => (
            <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)}
              className="lq-btn !min-h-[44px] !px-4 text-sm sm:!min-h-[38px]" data-active={mode === m} data-tone={mode === m ? "signal" : undefined}>
              {m === "simple" ? "Simple" : "Detailed"}
            </button>
          ))}
        </div>
      </div>

      <dl className="mt-6 grid grid-cols-1 gap-x-10 gap-y-7 lg:grid-cols-2">
        {PARTS.map((p) => (
          <div key={p.title}>
            <dt className="text-lg font-semibold">{p.title}</dt>
            <dd className="muted mt-1.5 max-w-[68ch] leading-relaxed">{mode === "simple" ? p.simple : p.detailed}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
