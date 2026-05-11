"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useYachtConfig, HULL_COLORS, ACCENT_COLORS, LIGHTING_PRESETS } from "@/hooks/useYachtConfig";

type Section = "hull" | "deck" | "accents" | "features" | "lighting";

export default function ConfiguratorUI() {
  const [activeSection, setActiveSection] = useState<Section>("hull");
  const config = useYachtConfig();

  const sections: { key: Section; label: string; icon: JSX.Element }[] = [
    { key: "hull", label: "Rumpf", icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 21l9-18 9 18H3zm9-18v18" /></svg> },
    { key: "deck", label: "Deck", icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 7h18M3 12h18M3 17h18" /></svg> },
    { key: "accents", label: "Akzente", icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" /></svg> },
    { key: "features", label: "Features", icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z" /></svg> },
    { key: "lighting", label: "Stimmung", icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" /></svg> },
  ];

  if (config.presentationMode) return null;

  return (
    <AnimatePresence>
      {config.configOpen && (
        <motion.div
          initial={{ x: 400, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 400, opacity: 0 }}
          transition={{ type: "spring", damping: 25, stiffness: 200 }}
          className="fixed right-0 top-0 bottom-0 w-[380px] z-40 flex flex-col
            max-md:w-full max-md:top-auto max-md:bottom-0 max-md:h-[55vh] max-md:rounded-t-3xl"
        >
          {/* Glass background */}
          <div className="absolute inset-0 bg-black/60 backdrop-blur-2xl border-l border-white/[0.06] max-md:border-l-0 max-md:border-t max-md:rounded-t-3xl" />

          <div className="relative flex flex-col h-full overflow-hidden">
            {/* Header */}
            <div className="px-6 pt-6 pb-4">
              <div className="flex items-center justify-between mb-1">
                <h2 className="text-white text-lg font-extralight tracking-wide" style={{ fontFamily: "'Playfair Display', serif" }}>
                  Yacht Konfigurator
                </h2>
                <button onClick={config.toggleConfig} className="w-8 h-8 rounded-full bg-white/5 flex items-center justify-center text-gray-400 hover:text-white hover:bg-white/10 transition-all">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>
              <p className="text-[10px] text-gray-600 tracking-[0.2em] uppercase">Gestalten Sie Ihre Traumyacht</p>
            </div>

            {/* Section tabs */}
            <div className="px-4 mb-4">
              <div className="flex gap-1 p-1 bg-white/[0.03] rounded-xl">
                {sections.map((s) => (
                  <button key={s.key} onClick={() => setActiveSection(s.key)}
                    className={`flex-1 py-2 rounded-lg text-[10px] tracking-wide transition-all ${
                      activeSection === s.key
                        ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                        : "text-gray-500 hover:text-white"
                    }`}>
                    <span className="flex justify-center mb-0.5">{s.icon}</span>
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto px-6 pb-6 scrollbar-thin">
              <AnimatePresence mode="wait">
                <motion.div key={activeSection} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.3 }}>
                  {activeSection === "hull" && <HullSection />}
                  {activeSection === "deck" && <DeckSection />}
                  {activeSection === "accents" && <AccentsSection />}
                  {activeSection === "features" && <FeaturesSection />}
                  {activeSection === "lighting" && <LightingSection />}
                </motion.div>
              </AnimatePresence>
            </div>

            {/* Presentation mode button */}
            <div className="px-6 pb-6 pt-2">
              <button onClick={config.togglePresentationMode}
                className="w-full py-3.5 rounded-xl bg-gradient-to-r from-amber-400 to-amber-600 text-black font-medium text-sm tracking-wide hover:shadow-lg hover:shadow-amber-500/20 transition-all">
                Präsentationsmodus
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// ─── HULL SECTION ──────────────────────────────────────────
function HullSection() {
  const { hullColor, hullMaterial, setHullColor, setHullMaterial } = useYachtConfig();

  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>Rumpffarbe</SectionLabel>
        <div className="grid grid-cols-4 gap-3">
          {HULL_COLORS.map((c) => (
            <button key={c.key} onClick={() => setHullColor(c.hex)}
              className={`group flex flex-col items-center gap-1.5 p-2.5 rounded-xl border transition-all ${
                hullColor === c.hex ? "border-amber-500/50 bg-amber-500/5" : "border-white/[0.04] hover:border-white/[0.1]"
              }`}>
              <div className="w-8 h-8 rounded-full border-2 border-white/10 shadow-lg transition-transform group-hover:scale-110"
                style={{ backgroundColor: c.hex }} />
              <span className="text-[9px] text-gray-500 text-center leading-tight">{c.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div>
        <SectionLabel>Material</SectionLabel>
        <div className="space-y-2">
          {(["glossy", "matte", "carbon"] as const).map((m) => (
            <button key={m} onClick={() => setHullMaterial(m)}
              className={`w-full text-left p-3 rounded-xl border transition-all ${
                hullMaterial === m ? "border-amber-500/50 bg-amber-500/5" : "border-white/[0.04] hover:border-white/[0.1]"
              }`}>
              <span className="text-white text-sm font-medium capitalize">{m === "glossy" ? "Hochglanz" : m === "matte" ? "Matt" : "Carbon Fiber"}</span>
              <p className="text-gray-600 text-[10px] mt-0.5">
                {m === "glossy" ? "Spiegelnde Oberfläche mit Clearcoat" : m === "matte" ? "Elegante matte Oberfläche" : "Racing-Grade Carbon Faser"}
              </p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── DECK SECTION ──────────────────────────────────────────
function DeckSection() {
  const { deckMaterial, setDeckMaterial } = useYachtConfig();

  const options = [
    { key: "teak" as const, label: "Burma-Teak", desc: "Handverlegtes Massivholz, rutschfest", color: "#8B6914" },
    { key: "white" as const, label: "White Composite", desc: "Modernes weißes Kunstdeck", color: "#E8E8E0" },
    { key: "dark" as const, label: "Dark Composite", desc: "Dunkles Premium-Composite", color: "#2C2C2C" },
  ];

  return (
    <div>
      <SectionLabel>Deck-Material</SectionLabel>
      <div className="space-y-2">
        {options.map((o) => (
          <button key={o.key} onClick={() => setDeckMaterial(o.key)}
            className={`w-full flex items-center gap-3 p-3 rounded-xl border transition-all ${
              deckMaterial === o.key ? "border-amber-500/50 bg-amber-500/5" : "border-white/[0.04] hover:border-white/[0.1]"
            }`}>
            <div className="w-10 h-10 rounded-lg border border-white/10" style={{ backgroundColor: o.color }} />
            <div className="text-left">
              <span className="text-white text-sm font-medium">{o.label}</span>
              <p className="text-gray-600 text-[10px]">{o.desc}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── ACCENTS SECTION ───────────────────────────────────────
function AccentsSection() {
  const { accentColor, setAccentColor } = useYachtConfig();

  const options = [
    { key: "gold" as const, label: "Gold", desc: "Klassisches Yacht-Gold" },
    { key: "silver" as const, label: "Silber", desc: "Modernes gebürstetes Silber" },
    { key: "rose-gold" as const, label: "Roségold", desc: "Warme Roségold-Akzente" },
    { key: "black-chrome" as const, label: "Black Chrome", desc: "Dunkles Chrom — sportlich" },
  ];

  return (
    <div>
      <SectionLabel>Akzentfarbe (Reling, Beschläge, Trim)</SectionLabel>
      <div className="grid grid-cols-2 gap-2">
        {options.map((o) => (
          <button key={o.key} onClick={() => setAccentColor(o.key)}
            className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${
              accentColor === o.key ? "border-amber-500/50 bg-amber-500/5" : "border-white/[0.04] hover:border-white/[0.1]"
            }`}>
            <div className="w-8 h-8 rounded-full border border-white/10 shadow-lg"
              style={{ backgroundColor: ACCENT_COLORS[o.key] }} />
            <span className="text-white text-xs font-medium">{o.label}</span>
            <span className="text-gray-600 text-[9px]">{o.desc}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── FEATURES SECTION ──────────────────────────────────────
function FeaturesSection() {
  const { features, toggleFeature } = useYachtConfig();

  const featureList = [
    { key: "jacuzzi" as const, label: "Jacuzzi", desc: "Whirlpool auf dem Flybridge", icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2 13c2-3 4-3 6 0s4 3 6 0 4-3 6 0M2 17c2-3 4-3 6 0s4 3 6 0 4-3 6 0" /></svg> },
    { key: "helipad" as const, label: "Helipad", desc: "Hubschrauberlandeplatz am Bug", icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 6h18M12 6v4m-4 0h8l2 5H6l2-5m4 5v4m-3 0h6" /></svg> },
    { key: "sunbathing" as const, label: "Sonnendeck", desc: "Gepolsterte Liegefläche", icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" /></svg> },
    { key: "pool" as const, label: "Infinity Pool", desc: "Eingelassener Pool auf dem Hauptdeck", icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2 20c2-2 4-2 6 0s4 2 6 0 4-2 6 0M12 4a2 2 0 100 4 2 2 0 000-4zM8 14l4-4 4 4" /></svg> },
  ];

  return (
    <div>
      <SectionLabel>Features ein-/ausschalten</SectionLabel>
      <div className="space-y-2">
        {featureList.map((f) => (
          <button key={f.key} onClick={() => toggleFeature(f.key)}
            className={`w-full flex items-center justify-between p-3.5 rounded-xl border transition-all ${
              features[f.key] ? "border-amber-500/50 bg-amber-500/5" : "border-white/[0.04] hover:border-white/[0.1]"
            }`}>
            <div className="flex items-center gap-3">
              <span className="text-amber-400/70">{f.icon}</span>
              <div className="text-left">
                <span className="text-white text-sm font-medium">{f.label}</span>
                <p className="text-gray-600 text-[10px]">{f.desc}</p>
              </div>
            </div>
            <div className={`w-10 h-5 rounded-full flex items-center transition-all ${
              features[f.key] ? "bg-amber-500 justify-end" : "bg-white/10 justify-start"
            }`}>
              <div className={`w-4 h-4 rounded-full mx-0.5 transition-all ${
                features[f.key] ? "bg-black" : "bg-gray-500"
              }`} />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── LIGHTING SECTION ──────────────────────────────────────
function LightingSection() {
  const { lightingMood, setLightingMood } = useYachtConfig();

  const moods = [
    { key: "mediterranean" as const, label: "Mediterranean Day", desc: "Helles Sonnenlicht, klares Wasser", iconLetter: "M", gradient: "from-sky-400 to-blue-500" },
    { key: "sunset" as const, label: "Sunset", desc: "Warmes Abendlicht, goldene Stunde", iconLetter: "S", gradient: "from-orange-400 to-red-500" },
    { key: "night" as const, label: "Night", desc: "Mondlicht, Yacht-Beleuchtung", iconLetter: "N", gradient: "from-indigo-800 to-slate-900" },
    { key: "storm" as const, label: "Storm", desc: "Dramatisch, cinematisch", iconLetter: "St", gradient: "from-gray-600 to-gray-800" },
  ];

  return (
    <div>
      <SectionLabel>Lichtstimmung</SectionLabel>
      <div className="grid grid-cols-2 gap-2">
        {moods.map((m) => (
          <button key={m.key} onClick={() => setLightingMood(m.key)}
            className={`group overflow-hidden rounded-xl border transition-all ${
              lightingMood === m.key ? "border-amber-500/50 ring-1 ring-amber-500/20" : "border-white/[0.04] hover:border-white/[0.1]"
            }`}>
            <div className={`h-16 bg-gradient-to-br ${m.gradient} flex items-center justify-center transition-transform group-hover:scale-105`}>
              <span className="text-white/80 text-lg font-light tracking-wider" style={{ fontFamily: "'Playfair Display', serif" }}>{m.iconLetter}</span>
            </div>
            <div className="p-2.5 bg-white/[0.02]">
              <span className="text-white text-xs font-medium block">{m.label}</span>
              <span className="text-gray-600 text-[9px]">{m.desc}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── Helpers ───────────────────────────────────────────────
function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-[10px] tracking-[0.2em] uppercase text-amber-400/50 mb-3 flex items-center gap-2">
      <span className="w-6 h-px bg-amber-500/30" />
      {children}
    </h3>
  );
}
