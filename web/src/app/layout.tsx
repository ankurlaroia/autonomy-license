import type { Metadata, Viewport } from "next";
import { Instrument_Serif, JetBrains_Mono, Public_Sans } from "next/font/google";
import { THEME_SCRIPT } from "@/lib/theme";
import "./globals.css";

// Public Sans: a civic face for an authority that issues permits. Instrument Serif: only the licence's engraved
// title. JetBrains Mono: only values that really are serials or hashes.
const sans = Public_Sans({ variable: "--font-ui", subsets: ["latin"] });
const serif = Instrument_Serif({ variable: "--font-engraved", subsets: ["latin"], weight: "400", style: ["normal", "italic"] });
// not preloaded: serials are small and below the headline, so the mono face shouldn't compete with the UI face
const mono = JetBrains_Mono({ variable: "--font-serial", subsets: ["latin"], weight: ["400", "500"], preload: false });

export const metadata: Metadata = {
  title: "Autonomy License",
  description: "An AI network agent acts alone only while calibration evidence says it may.",
};

// viewport-fit: the fixed dock clears a phone's home bar through env(safe-area-inset-bottom).
export const viewport: Viewport = { width: "device-width", initialScale: 1, viewportFit: "cover" };

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning
      className={`${sans.variable} ${serif.variable} ${mono.variable} antialiased`}>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
