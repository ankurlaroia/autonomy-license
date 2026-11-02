"use client";

import { useSimple } from "@/lib/simple";

const POINTS: [string, string][] = [
  ["The problem", "AI can diagnose network faults faster than people, but nobody wants it changing a live network on a hunch."],
  ["The test", "Before it may act alone, the AI is checked on past faults it has never seen. The pass mark is fixed in advance: at most 5 wrong diagnoses in 100, even allowing for bad luck."],
  ["The licence", "Passing earns a signed licence that expires. When the AI is sure enough, it fixes the fault itself. When it isn't, a person decides."],
  ["The limits", "Some rules hold no matter what, for the AI and for people: for example, never change more than 3 cell sites at once."],
  ["The off switch", "A person can withdraw the licence at any moment, and the very next decision goes back to people."],
  ["Working together", "Smaller operators can pool their test results, without sharing their data, and warn each other when something goes wrong."],
];

export default function SimpleIntro() {
  const simple = useSimple();
  if (!simple) return null;
  return (
    <section className="glass reveal mt-8 p-5 sm:p-7" aria-labelledby="simple-intro">
      <h2 id="simple-intro" className="text-2xl font-semibold tracking-[-0.02em]">The idea in one minute</h2>
      <dl className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {POINTS.map(([k, v]) => (
          <div key={k} className="glass-card p-4">
            <dt className="font-semibold">{k}</dt>
            <dd className="muted mt-1 text-body leading-relaxed">{v}</dd>
          </div>
        ))}
      </dl>
      <p className="faint mt-4 text-sm">
        What we can honestly claim: the test limits wrong diagnoses, not whether a fix is safe; the hard rules handle
        that. Today the numbers come from practice data and a simulated network.
      </p>
    </section>
  );
}
