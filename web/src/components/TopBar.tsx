import Link from "next/link";

import SimpleToggle from "@/components/SimpleToggle";
import ThemeToggle from "@/components/ThemeToggle";

const TABS = [
  { href: "/", label: "Console", key: "console" },
  { href: "/video", label: "Video", key: "video" },
  { href: "/help", label: "Help", key: "help" },
] as const;

export default function TopBar({ active, source, onStage, onLive, liveOpen }: {
  active: (typeof TABS)[number]["key"]; source?: string; onStage?: () => void; onLive?: () => void; liveOpen?: boolean;
}) {
  return (
    <nav className="glass flex items-center justify-between gap-1 py-1.5 pl-2.5 pr-1.5 sm:gap-3 sm:py-2 sm:pl-3.5 sm:pr-2" style={{ borderRadius: 999 }}>
      <Link href="/" aria-label="Autonomy License, console" className={`flex items-center gap-3 rounded-full max-[399px]:hidden focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--signal)]`}>
        <svg aria-hidden width="32" height="32" viewBox="0 0 32 32">
          <path d="M16 2.5l11.7 6.75v13.5L16 29.5 4.3 22.75V9.25z" style={{ fill: "rgb(var(--signal-rgb) / .12)" }} stroke="var(--signal)" strokeWidth="1.6" />
          <path d="M10.5 16.2l3.6 3.6 7.4-7.6" fill="none" stroke="var(--signal)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="hidden whitespace-nowrap leading-tight md:block">
          <span className="block text-lg font-semibold tracking-tight">Autonomy License</span>
          <span className="faint hidden text-caption xl:block">Breaking Barriers Hackathon, FYUZ 2026</span>
        </span>
      </Link>

      <div role="tablist" aria-label="Pages" className="flex gap-1 rounded-full bg-sink p-1">
        {TABS.map((t) => (
          <Link key={t.key} href={t.href} role="tab" aria-selected={active === t.key}
            className="lq-btn !min-h-[44px] !px-2.5 text-sm max-[359px]:!px-1.5 sm:!min-h-[38px] sm:!px-4" data-active={active === t.key}
            data-tone={active === t.key ? "signal" : undefined}>
            {t.label}
          </Link>
        ))}
      </div>

      <div className="flex items-center gap-1 sm:gap-2">
        {onLive && (
          <button type="button" onClick={onLive} aria-pressed={liveOpen} aria-label="Live" className="lq-btn !min-h-[44px] !w-[44px] !px-0 text-sm sm:!min-h-[38px] sm:!w-auto sm:!px-3" data-tone="signal"
            title="Send real calls to the AWS services and see what each one recorded">
            <span aria-hidden className="h-2 w-2 rounded-full bg-signal" />
            <span className="hidden sm:inline">Live</span>
          </button>
        )}
        {onStage && (
          <button type="button" onClick={onStage} className="lq-btn hidden !min-h-[38px] !w-[38px] !px-0 sm:inline-flex"
            aria-label="Stage mode, for a projector" title="Stage mode, for a projector (S)">
            <svg aria-hidden width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="4" width="18" height="12" rx="1.5" />
              <path d="M12 16v4M8 20h8" />
            </svg>
          </button>
        )}
        <ThemeToggle />
        <SimpleToggle />
        <span className="pill hidden lg:inline-flex">Operator A</span>
        {source === "telelogs" ? (
          <span className="pill hidden whitespace-nowrap sm:inline-flex" data-tone="signal" title="Real TeleLogs test incidents, scored by att/OTel-LLM-8.3B-Classification">
            TeleLogs data
          </span>
        ) : source ? (
          <span className="pill hidden whitespace-nowrap sm:inline-flex" data-tone="amber" title="Every number comes from a synthetic stand-in with the TeleLogs shape">
            Synthetic data
          </span>
        ) : null}
      </div>
    </nav>
  );
}
