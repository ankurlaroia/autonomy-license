"use client";

import { useSyncExternalStore } from "react";

// Light or dark. A per-viewer preference: the system setting until the viewer picks one, then their pick, kept in
// localStorage (guarded: storage can be blocked). The theme lives on <html data-theme>, set before first paint by
// THEME_SCRIPT, so the stylesheet alone decides every colour and there is no flash.
export type Theme = "light" | "dark";
const KEY = "al-theme";
const EVENT = "al-theme-change";

// Runs inline in <head>, before the body paints. Kept tiny and self-contained: no imports, no React.
export const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem("${KEY}")}catch(e){}if(t!=="light"&&t!=="dark")t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";document.documentElement.dataset.theme=t})()`;

function read(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function subscribe(cb: () => void) {
  window.addEventListener(EVENT, cb);
  return () => window.removeEventListener(EVENT, cb);
}

export function setTheme(t: Theme) {
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem(KEY, t);
  } catch {}
  window.dispatchEvent(new Event(EVENT));
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, read, () => "dark");
}
