"use client";

import { animate, useReducedMotion } from "motion/react";
import { useEffect, useState } from "react";

// The licence ceremony: one timeline shared by the calibration chart (Decision) and the licence (LicenceDoc), so
// issuing a licence reads as a single event. Every beat is real data: thresholds appear in the order the
// fixed-sequence test ran them, the licence fills in as each value is decided, and the seal lands when the test ends.
// Seconds from the moment the result arrives.
export type Ceremony = { firstPoint: number; step: number; decided: number; seal: number };

export const EASE_OUT: [number, number, number, number] = [0.2, 0.8, 0.2, 1];

/** Timings for a test that tried `steps` thresholds (0 for a re-certify, which has no chart). */
export function ceremony(steps: number): Ceremony {
  const step = steps ? Math.min(0.32, 1.6 / steps) : 0;   // long sequences compress; the whole test stays under 2 s
  const firstPoint = steps ? 0.4 : 0;
  const decided = firstPoint + steps * step + 0.1;
  return { firstPoint, step, decided, seal: decided + 0.55 };
}

/** A number that counts up from 0 once, then holds. Shows the final value at once under reduced motion. */
export function useCountUp(to: number, delay: number, duration = 0.8): number {
  const reduce = useReducedMotion();
  const [v, setV] = useState(0);
  useEffect(() => {
    if (reduce) return;
    const c = animate(0, to, { duration, delay, ease: EASE_OUT, onUpdate: setV });
    return () => c.stop();
  }, [to, delay, duration, reduce]);
  return reduce ? to : v;
}

/** Text that types itself in, as a serial number would be stamped. Whole text at once under reduced motion. */
export function useTyped(text: string, delay: number, perChar = 0.06): string {
  const reduce = useReducedMotion();
  const [n, setN] = useState(0);
  useEffect(() => {
    if (reduce) return;
    const c = animate(0, text.length, { duration: text.length * perChar, delay, ease: "linear", onUpdate: (x) => setN(Math.round(x)) });
    return () => c.stop();
  }, [text, delay, perChar, reduce]);
  return reduce ? text : text.slice(0, n);
}
