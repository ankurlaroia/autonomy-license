"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";

// The Cedar statements the gateway evaluates, fetched once per page from the API (api/server.py /policies),
// so the console quotes the deployed text and never a copy of it.
let cache: Record<string, string> | null = null;
let pending: Promise<Record<string, string>> | null = null;

export function usePolicies(): Record<string, string> | null {
  const [p, setP] = useState(cache);
  useEffect(() => {
    if (cache) return;
    pending ??= api.policies().then((r) => (cache = r.policies));
    pending.then(setP).catch(() => { pending = null; });
  }, []);
  return p;
}

/** A statement split for display: its comment, effect and condition block, kept verbatim. */
export function splitStatement(text: string): { comment: string; effect: string; condition: string } {
  const lines = text.split("\n");
  const at = lines.findIndex((l) => /^\s*(when|unless)\b/.test(l));
  return {
    comment: lines[0].replace(/^\/\/\s*/, ""),
    effect: (lines[1] ?? "").trim().split("(")[0],
    condition: at < 0 ? "" : lines.slice(at).join("\n").trim(),
  };
}
