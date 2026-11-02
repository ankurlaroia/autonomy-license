"use client";

// A radio-planning map: each hexagon is one cell's coverage, the dot is its site. The few lit cells take the
// colour of the latest decision; a ripple answers each applied action at one site.

const R = 46;                                   // hex circumradius
const W = Math.sqrt(3) * R;
const CELLS = Array.from({ length: 12 * 15 }, (_, i) => {
  const row = Math.floor(i / 15);
  const col = i % 15;
  return { x: col * W + (row % 2) * (W / 2), y: row * R * 1.5 };
});
const hex = (x: number, y: number) =>
  "M" + Array.from({ length: 6 }, (_, k) => {
    const a = (Math.PI / 3) * k + Math.PI / 6;
    return `${(x + R * Math.cos(a)).toFixed(1)},${(y + R * Math.sin(a)).toFixed(1)}`;
  }).join("L") + "Z";
const LIT = new Set([33, 34, 48, 63, 79, 95, 96, 111, 127, 142]);   // a cluster around the incident
const dot = (x: number, y: number, r = 1.6) => `M${x - r},${y}a${r},${r} 0 1,0 ${2 * r},0a${r},${r} 0 1,0 ${-2 * r},0`;
// The unlit map never changes, so it is two paths (outlines, sites) rather than 340 elements to style and lay out.
const GRID = CELLS.filter((_, i) => !LIT.has(i)).map((p) => hex(p.x, p.y)).join("");
const SITES = CELLS.filter((_, i) => !LIT.has(i)).map((p) => dot(p.x, p.y)).join("");

const MOOD: Record<string, string> = {
  allow: "var(--signal)", deny: "var(--ember)", human: "var(--amber)", revoked: "var(--withdrawn)", idle: "var(--idle)",
};

export default function Backdrop({ mood, pulse }: { mood: keyof typeof MOOD; pulse: number }) {
  const c = MOOD[mood] ?? MOOD.idle;
  const lit = [...LIT];
  const site = CELLS[lit[(pulse * 7) % lit.length]];
  return (
    <div className="backdrop" data-mood={mood} aria-hidden>
      <svg className="hexmap absolute inset-0 h-full w-full" viewBox="0 0 1200 900" preserveAspectRatio="xMidYMid slice">
        <path d={GRID} fill="none" stroke="var(--hex-line)" strokeWidth={1} style={{ strokeOpacity: "calc(0.07 * var(--hex-strength))" }} />
        <path d={SITES} fill="var(--hex-dot)" style={{ fillOpacity: "calc(0.18 * var(--hex-strength))" }} />
        {lit.map((i) => (
          <g key={i}>
            <path d={hex(CELLS[i].x, CELLS[i].y)} fill={c} fillOpacity={0.07} stroke={c} strokeWidth={1} style={{ strokeOpacity: 0.35 }} />
            <circle cx={CELLS[i].x} cy={CELLS[i].y} r={1.6} fill="var(--hex-dot)" style={{ fillOpacity: 0.6 }} />
          </g>
        ))}
        {pulse > 0 && <circle key={pulse} className="ripple" cx={site.x} cy={site.y} r={26} fill="none" stroke={c} strokeWidth={1.5} />}
      </svg>
      <div className="absolute inset-0" style={{ background: "radial-gradient(85% 70% at 50% 35%, transparent 30%, var(--vignette))" }} />
    </div>
  );
}
