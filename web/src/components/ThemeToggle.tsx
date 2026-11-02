"use client";

import { setTheme, useTheme } from "@/lib/theme";

// Names the mode it switches to, so the label is the action.
export default function ThemeToggle() {
  const t = useTheme();
  const next = t === "dark" ? "light" : "dark";
  return (
    <button type="button" onClick={() => setTheme(next)} className="lq-btn !min-h-[38px] !w-[38px] !px-0"
      aria-label={`Switch to ${next} mode`} title={`Switch to ${next} mode`}>
      {t === "dark" ? (
        <svg aria-hidden width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round">
          <circle cx="12" cy="12" r="4.2" />
          <path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6" />
        </svg>
      ) : (
        <svg aria-hidden width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinejoin="round">
          <path d="M20.2 14.6A8.4 8.4 0 0 1 9.4 3.8a8.4 8.4 0 1 0 10.8 10.8z" />
        </svg>
      )}
    </button>
  );
}
