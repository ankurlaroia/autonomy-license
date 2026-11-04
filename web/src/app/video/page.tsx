import type { Metadata } from "next";

import Backdrop from "@/components/Backdrop";
import ProjectOverview from "@/components/ProjectOverview";
import TopBar from "@/components/TopBar";

export const metadata: Metadata = {
  title: "Video · Autonomy License",
  description: "A one-minute film on how an AI agent earns a licence to fix a network, and an overview of the project in simple or detailed terms.",
};

export default function VideoPage() {
  return (
    <>
      <Backdrop mood="idle" pulse={0} />
      <div className="mx-auto max-w-[1240px] px-4 pb-24 pt-5 sm:px-6">
        <TopBar active="video" />

        <main>
          <section className="mt-6" aria-label="Film">
            <video className="glass block aspect-video w-full overflow-hidden" src="/autonomy-license-film-ruth.mp4"
              poster="/autonomy-license-film.jpg" controls playsInline preload="metadata"
              aria-label="One-minute narrated illustration: a cell tower fault, and how an AI agent earns a licence to fix it" />
            <p className="faint mt-3 text-sm">An illustration of the idea. The network in the console&apos;s demo is simulated.</p>
          </section>

          <ProjectOverview />
        </main>
      </div>
    </>
  );
}
