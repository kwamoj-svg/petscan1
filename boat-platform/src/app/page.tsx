"use client";

import Link from "next/link";
import { motion } from "framer-motion";

const fadeUp = {
  initial: { opacity: 0, y: 40 },
  animate: { opacity: 1, y: 0 },
};

export default function HomePage() {
  return (
    <div className="min-h-screen bg-[#050508] text-white overflow-hidden" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>

      {/* ═══ NAVBAR ═══ */}
      <nav className="fixed top-0 left-0 right-0 z-50 backdrop-blur-2xl bg-[#050508]/60 border-b border-white/[0.03]">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-300 to-amber-600 flex items-center justify-center shadow-lg shadow-amber-500/10">
              <span className="text-black text-sm font-bold tracking-tighter">BC</span>
            </div>
            <span className="text-white/80 font-extralight text-lg tracking-[0.1em]" style={{ fontFamily: "'Playfair Display', serif" }}>
              BoatConnect
            </span>
          </Link>
          <div className="hidden md:flex items-center gap-8">
            <Link href="/configurator" className="text-gray-500 text-sm hover:text-white transition-colors">Experience</Link>
            <Link href="/configurator3d" className="text-gray-500 text-sm hover:text-white transition-colors">3D Konfigurator</Link>
            <Link href="/dealer/login" className="text-gray-500 text-sm hover:text-white transition-colors">Partner</Link>
            <Link href="/configurator"
              className="px-5 py-2 rounded-full bg-gradient-to-r from-amber-400 to-amber-600 text-black text-sm font-medium hover:shadow-lg hover:shadow-amber-500/20 transition-all">
              Start Your Match
            </Link>
          </div>
        </div>
      </nav>

      {/* ═══ HERO ═══ */}
      <section className="relative min-h-screen flex items-center justify-center">
        <div className="absolute inset-0">
          <img
            src="https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=1920&h=1080&fit=crop"
            alt="Luxury Yacht"
            className="w-full h-full object-cover opacity-30"
          />
          <div className="absolute inset-0 bg-gradient-to-b from-[#050508] via-[#050508]/60 to-[#050508]" />
        </div>

        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-amber-500/[0.03] rounded-full blur-[200px]" />

        <div className="relative z-10 text-center px-6 max-w-5xl mx-auto">
          <motion.p {...fadeUp} transition={{ duration: 0.8, delay: 0.2 }}
            className="text-amber-400/60 text-xs tracking-[0.4em] uppercase mb-8">
            AI-Powered Yacht Matching
          </motion.p>

          <motion.h1 {...fadeUp} transition={{ duration: 1, delay: 0.4 }}
            className="text-5xl sm:text-6xl md:text-8xl font-extralight leading-[1.05] tracking-tight mb-8"
            style={{ fontFamily: "'Playfair Display', serif" }}>
            Find your perfect<br />
            <span className="bg-gradient-to-r from-amber-300 via-amber-400 to-amber-600 bg-clip-text text-transparent">
              yacht experience
            </span>
          </motion.h1>

          <motion.p {...fadeUp} transition={{ duration: 0.8, delay: 0.6 }}
            className="text-gray-400 text-lg md:text-xl max-w-2xl mx-auto mb-12 font-light leading-relaxed">
            Keine Suche. Keine Filter. Nur eine intelligente,
            KI-gestützte Experience, die Ihr perfektes Boot findet.
          </motion.p>

          <motion.div {...fadeUp} transition={{ duration: 0.8, delay: 0.8 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link href="/configurator"
              className="group px-10 py-4 rounded-full bg-gradient-to-r from-amber-400 to-amber-600 text-black font-semibold text-base tracking-wide hover:shadow-2xl hover:shadow-amber-500/25 transition-all duration-500 flex items-center gap-3">
              Start Your Match
              <svg className="w-5 h-5 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" /></svg>
            </Link>
            <Link href="/configurator3d"
              className="px-10 py-4 rounded-full border border-white/[0.08] text-gray-300 font-light text-base hover:border-white/[0.15] hover:text-white transition-all duration-500 flex items-center gap-3 backdrop-blur-sm">
              3D Konfigurator
            </Link>
          </motion.div>
        </div>

        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2 }}
          className="absolute bottom-10 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2">
          <span className="text-gray-600 text-[9px] tracking-[0.3em] uppercase">Entdecken</span>
          <motion.div animate={{ y: [0, 6, 0] }} transition={{ repeat: Infinity, duration: 2 }}
            className="w-5 h-8 rounded-full border border-white/[0.08] flex justify-center pt-1.5">
            <div className="w-1 h-1.5 rounded-full bg-amber-500/60" />
          </motion.div>
        </motion.div>
      </section>

      {/* ═══ HOW IT WORKS ═══ */}
      <section className="py-32 px-6">
        <div className="max-w-6xl mx-auto">
          <motion.div {...fadeUp} viewport={{ once: true }} className="text-center mb-20">
            <p className="text-amber-400/50 text-xs tracking-[0.3em] uppercase mb-4">How It Works</p>
            <h2 className="text-4xl md:text-5xl font-extralight tracking-tight" style={{ fontFamily: "'Playfair Display', serif" }}>
              Drei Schritte zu Ihrem<br /><span className="text-amber-400">perfekten Match</span>
            </h2>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {[
              { num: "01", title: "Erzählen Sie uns", desc: "Beantworten Sie luxuriös gestaltete Fragen zu Lifestyle, Budget und Wünschen." },
              { num: "02", title: "KI analysiert", desc: "Unsere KI durchsucht tausende Boote nach Ihrem perfekten Match." },
              { num: "03", title: "Ihr Match", desc: "Personalisierte Empfehlungen mit emotionalen Beschreibungen und direktem Kontakt." },
            ].map((step, i) => (
              <motion.div key={i} {...fadeUp} transition={{ delay: i * 0.2 }} viewport={{ once: true }}
                className="group relative p-8 rounded-3xl border border-white/[0.04] bg-white/[0.01] hover:bg-white/[0.03] hover:border-white/[0.08] transition-all duration-700">
                <span className="text-5xl font-extralight text-amber-400/30 mb-6 block" style={{ fontFamily: "'Playfair Display', serif" }}>{step.num}</span>
                <div className="flex items-center gap-3 mb-3">
                  <span className="text-amber-500/30 text-sm font-mono">{step.num}</span>
                  <h3 className="text-white text-xl font-light">{step.title}</h3>
                </div>
                <p className="text-gray-500 text-sm leading-relaxed">{step.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ CATEGORIES ═══ */}
      <section className="py-20 px-6">
        <div className="max-w-7xl mx-auto">
          <motion.div {...fadeUp} viewport={{ once: true }} className="text-center mb-16">
            <p className="text-amber-400/50 text-xs tracking-[0.3em] uppercase mb-4">Kategorien</p>
            <h2 className="text-4xl md:text-5xl font-extralight tracking-tight" style={{ fontFamily: "'Playfair Display', serif" }}>
              Jede Klasse. <span className="text-amber-400">Jeder Traum.</span>
            </h2>
          </motion.div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Superyachten", img: "https://images.unsplash.com/photo-1621277224630-81a0a5df4a17?w=600&h=400&fit=crop", price: "ab 5M €" },
              { label: "Motoryachten", img: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=600&h=400&fit=crop", price: "ab 200K €" },
              { label: "Katamarane", img: "https://images.unsplash.com/photo-1559494007-9f5847c49d94?w=600&h=400&fit=crop", price: "ab 150K €" },
              { label: "Segelboote", img: "https://images.unsplash.com/photo-1540946485063-a40da27545f8?w=600&h=400&fit=crop", price: "ab 30K €" },
              { label: "Sportboote", img: "https://images.unsplash.com/photo-1605281317010-fe5ffe798166?w=600&h=400&fit=crop", price: "ab 20K €" },
              { label: "Elektroboote", img: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=600&h=400&fit=crop", price: "ab 30K €" },
              { label: "Jetskis", img: "https://images.unsplash.com/photo-1626447857058-2ba6a8868cb5?w=600&h=400&fit=crop", price: "ab 5K €" },
              { label: "Explorer", img: "https://images.unsplash.com/photo-1605281317010-fe5ffe798166?w=600&h=400&fit=crop", price: "ab 1M €" },
            ].map((cat, i) => (
              <Link href="/configurator" key={i}>
                <motion.div {...fadeUp} transition={{ delay: i * 0.05 }} viewport={{ once: true }}
                  className="group relative rounded-2xl overflow-hidden cursor-pointer aspect-[4/3]">
                  <img src={cat.img} alt={cat.label} className="w-full h-full object-cover transition-transform duration-1000 group-hover:scale-110" />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent" />
                  <div className="absolute bottom-4 left-4 right-4">
                    <h3 className="text-white text-sm font-medium">{cat.label}</h3>
                    <p className="text-amber-400/70 text-xs">{cat.price}</p>
                  </div>
                </motion.div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ CTA ═══ */}
      <section className="py-32 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div {...fadeUp} viewport={{ once: true }}>
            <p className="text-amber-400/50 text-xs tracking-[0.3em] uppercase mb-6">Bereit?</p>
            <h2 className="text-4xl md:text-6xl font-extralight tracking-tight mb-8" style={{ fontFamily: "'Playfair Display', serif" }}>
              Starten Sie Ihre<br />
              <span className="bg-gradient-to-r from-amber-300 to-amber-600 bg-clip-text text-transparent">persönliche Experience</span>
            </h2>
            <p className="text-gray-500 text-base mb-12 max-w-lg mx-auto">
              Unverbindlich. Kostenlos. KI-gestützt. In wenigen Minuten zu Ihrem perfekten Match.
            </p>
            <Link href="/configurator"
              className="inline-flex items-center gap-3 px-12 py-5 rounded-full bg-gradient-to-r from-amber-400 to-amber-600 text-black font-semibold text-lg tracking-wide hover:shadow-2xl hover:shadow-amber-500/25 transition-all duration-500">
              Start Your Match
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" /></svg>
            </Link>
          </motion.div>
        </div>
      </section>

      {/* ═══ PARTNER SECTION ═══ */}
      <section className="py-20 px-6 border-t border-white/[0.03]">
        <div className="max-w-6xl mx-auto">
          <div className="grid md:grid-cols-2 gap-16 items-center">
            <div>
              <p className="text-amber-400/50 text-xs tracking-[0.3em] uppercase mb-4">B2B Platform</p>
              <h3 className="text-3xl font-extralight mb-4" style={{ fontFamily: "'Playfair Display', serif" }}>
                Hotels. Concierge. Broker. <span className="text-amber-400">Händler.</span>
              </h3>
              <p className="text-gray-500 text-sm leading-relaxed mb-8">
                Werden Sie Teil unserer kuratierten Plattform. Erhalten Sie qualifizierte Leads,
                nutzen Sie unser KI-Matching und erreichen Sie kaufbereite Kunden.
              </p>
              <Link href="/dealer/login" className="inline-flex items-center gap-2 text-amber-400 text-sm hover:text-amber-300 transition-colors">
                Partner werden →
              </Link>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {[
                { label: "Hotels & Resorts", abbr: "H", desc: "Yacht-Experience für Gäste" },
                { label: "Concierge", abbr: "C", desc: "KI-gestütztes Matching" },
                { label: "Yachtbroker", abbr: "YB", desc: "Qualifizierte Kauf-Leads" },
                { label: "Charterfirmen", abbr: "CF", desc: "Charter-Anfragen direkt" },
              ].map((p, i) => (
                <div key={i} className="p-5 rounded-2xl border border-white/[0.04] bg-white/[0.01]">
                  <span className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-400/10 to-amber-600/10 border border-amber-500/20 flex items-center justify-center text-amber-400 text-sm font-medium mb-3" style={{ fontFamily: "'Playfair Display', serif" }}>{p.abbr}</span>
                  <h4 className="text-white text-sm font-medium mb-1">{p.label}</h4>
                  <p className="text-gray-600 text-xs">{p.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ═══ FOOTER ═══ */}
      <footer className="py-12 px-6 border-t border-white/[0.03]">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-amber-300 to-amber-600 flex items-center justify-center">
              <span className="text-black text-[10px] font-bold">BC</span>
            </div>
            <span className="text-gray-600 text-sm">BoatConnect — AI Yacht Matching Platform</span>
          </div>
          <div className="flex gap-6 text-xs text-gray-600">
            <Link href="/configurator" className="hover:text-white transition-colors">Experience</Link>
            <Link href="/configurator3d" className="hover:text-white transition-colors">3D Konfigurator</Link>
            <span>Impressum</span>
            <span>Datenschutz</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
