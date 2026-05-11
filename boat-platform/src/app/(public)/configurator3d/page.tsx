"use client";

import dynamic from "next/dynamic";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { useYachtConfig } from "@/hooks/useYachtConfig";

// Dynamic import for Three.js (no SSR)
const ConfiguratorScene = dynamic(
  () => import("@/components/configurator3d/ConfiguratorScene"),
  { ssr: false }
);
const ConfiguratorUI = dynamic(
  () => import("@/components/configurator3d/ConfiguratorUI"),
  { ssr: false }
);

export default function Configurator3DPage() {
  const [loading, setLoading] = useState(true);
  const { configOpen, toggleConfig, presentationMode, togglePresentationMode } = useYachtConfig();

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 2500);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="fixed inset-0 bg-[#050508] overflow-hidden">
      {/* ═══ LOADING SCREEN ═══ */}
      <AnimatePresence>
        {loading && (
          <motion.div
            exit={{ opacity: 0 }}
            transition={{ duration: 1 }}
            className="fixed inset-0 z-[100] bg-[#050508] flex flex-col items-center justify-center"
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              className="mb-8"
            >
              <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-amber-300 to-amber-600 flex items-center justify-center shadow-2xl shadow-amber-500/20">
                <span className="text-black text-2xl font-bold tracking-tighter">BC</span>
              </div>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 0.6 }}
              className="text-white text-2xl font-extralight tracking-[0.2em] mb-6"
              style={{ fontFamily: "'Playfair Display', serif" }}
            >
              YACHT CONFIGURATOR
            </motion.h1>

            {/* Loading bar */}
            <div className="w-48 h-[2px] bg-white/[0.06] rounded-full overflow-hidden">
              <motion.div
                initial={{ width: "0%" }}
                animate={{ width: "100%" }}
                transition={{ duration: 2.2, ease: "easeInOut" }}
                className="h-full bg-gradient-to-r from-amber-400 to-amber-600 rounded-full"
              />
            </div>

            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.8 }}
              className="mt-4 text-gray-600 text-xs tracking-[0.15em]"
            >
              Lade 3D-Szene...
            </motion.p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ═══ 3D SCENE ═══ */}
      <ConfiguratorScene />

      {/* ═══ TOP BAR ═══ */}
      <AnimatePresence>
        {!presentationMode && (
          <motion.div
            initial={{ y: -60, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -60, opacity: 0 }}
            transition={{ duration: 0.5 }}
            className="fixed top-0 left-0 right-0 z-30 px-6 py-4"
          >
            <div className="flex items-center justify-between">
              <Link href="/" className="flex items-center gap-3 group">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-300/80 to-amber-600/80 backdrop-blur-sm flex items-center justify-center shadow-lg shadow-amber-500/10">
                  <span className="text-black text-sm font-bold tracking-tighter">BC</span>
                </div>
                <div>
                  <span className="text-white/80 text-sm font-extralight tracking-[0.1em] block" style={{ fontFamily: "'Playfair Display', serif" }}>
                    BoatConnect
                  </span>
                  <span className="text-gray-600 text-[9px] tracking-[0.2em] uppercase">3D Konfigurator</span>
                </div>
              </Link>

              <div className="flex items-center gap-3">
                {/* Config toggle */}
                {!configOpen && (
                  <motion.button
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    onClick={toggleConfig}
                    className="w-10 h-10 rounded-xl bg-white/5 backdrop-blur-sm border border-white/[0.06] flex items-center justify-center text-gray-400 hover:text-white hover:bg-white/10 transition-all"
                  >
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                  </motion.button>
                )}

                {/* Back to matching */}
                <Link href="/configurator"
                  className="px-4 py-2 rounded-xl bg-white/5 backdrop-blur-sm border border-white/[0.06] text-gray-400 text-xs hover:text-white hover:bg-white/10 transition-all">
                  ← Matching
                </Link>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ═══ CONFIGURATOR UI ═══ */}
      <ConfiguratorUI />

      {/* ═══ PRESENTATION MODE EXIT ═══ */}
      <AnimatePresence>
        {presentationMode && (
          <motion.button
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={togglePresentationMode}
            className="fixed bottom-8 left-1/2 -translate-x-1/2 z-30 px-6 py-3 rounded-full bg-black/40 backdrop-blur-sm border border-white/[0.06] text-gray-400 text-xs hover:text-white transition-all"
          >
            ESC · Präsentation beenden
          </motion.button>
        )}
      </AnimatePresence>

      {/* ═══ BOTTOM INFO ═══ */}
      <AnimatePresence>
        {!presentationMode && !configOpen && (
          <motion.div
            initial={{ y: 60, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 60, opacity: 0 }}
            className="fixed bottom-8 left-8 z-30"
          >
            <p className="text-gray-600 text-[10px] tracking-[0.15em] uppercase mb-1">Interaktiv</p>
            <p className="text-gray-500 text-xs">Ziehen zum Drehen · Scrollen zum Zoomen</p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
