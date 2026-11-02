"use client";

import { setSimple, useSimple } from "@/lib/simple";

export default function SimpleToggle() {
  const on = useSimple();
  return (
    <button type="button" role="switch" aria-checked={on} aria-label="Simple view" onClick={() => setSimple(!on)}
      className="lq-btn !min-h-[38px] !gap-2 !px-3 whitespace-nowrap text-sm" data-tone={on ? "amber" : undefined}
      title={on ? "Back to the full technical view" : "Explain everything in plain words"}>
      <span aria-hidden className="relative inline-block h-5 w-9 rounded-full border border-fg/15 bg-sink shadow-[inset_0_1px_2px_rgb(0_0_0/.25)]">
        <span className="absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-[left] duration-300"
          style={{ left: on ? 18 : 2 }} />
      </span>
      <span className="hidden min-[380px]:inline">Simple<span className="hidden lg:inline"> view</span></span>
    </button>
  );
}
