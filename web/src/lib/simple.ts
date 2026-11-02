"use client";

import { useSyncExternalStore } from "react";

// "Simple view": plain-language wording for people new to the system. A per-viewer preference,
// so it lives in localStorage (guarded: storage can be blocked) and is shared across tabs and pages.
const KEY = "al-simple-view";
const EVENT = "al-simple-change";

function read(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

function subscribe(cb: () => void) {
  window.addEventListener(EVENT, cb);
  window.addEventListener("storage", cb);
  return () => {
    window.removeEventListener(EVENT, cb);
    window.removeEventListener("storage", cb);
  };
}

export function setSimple(on: boolean) {
  try {
    localStorage.setItem(KEY, on ? "1" : "0");
  } catch {}
  window.dispatchEvent(new Event(EVENT));
}

export function useSimple(): boolean {
  return useSyncExternalStore(subscribe, read, () => false);
}
