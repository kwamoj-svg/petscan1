import Link from "next/link";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";

const CATEGORIES = [
  { key: "YACHT", label: "Yachten", icon: "M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4", img: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=400&h=300&fit=crop" },
  { key: "SPORTBOAT", label: "Sportboote", icon: "M13 10V3L4 14h7v7l9-11h-7z", img: "https://images.unsplash.com/photo-1605281317010-fe5ffe798166?w=400&h=300&fit=crop" },
  { key: "SAILBOAT", label: "Segelboote", icon: "M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4", img: "https://images.unsplash.com/photo-1540946485063-a40da27545f8?w=400&h=300&fit=crop" },
  { key: "CATAMARAN", label: "Katamarane", icon: "M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4", img: "https://images.unsplash.com/photo-1559494007-9f5847c49d94?w=400&h=300&fit=crop" },
  { key: "JETSKI", label: "Jetskis", icon: "M13 10V3L4 14h7v7l9-11h-7z", img: "https://images.unsplash.com/photo-1626447857058-2ba6a8868cb5?w=400&h=300&fit=crop" },
  { key: "FISHING", label: "Angelboote", icon: "M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4", img: "https://images.unsplash.com/photo-1544551763-46a013bb70d5?w=400&h=300&fit=crop" },
];

const STATS = [
  { value: "2.500+", label: "Boote gelistet" },
  { value: "180+", label: "Verifizierte Händler" },
  { value: "15.000+", label: "Erfolgreiche Vermittlungen" },
  { value: "12", label: "Länder" },
];

const STEPS = [
  { step: "01", title: "Konfigurieren", desc: "Wählen Sie Bootstyp, Größe, Motor und Ausstattung nach Ihren Wünschen." },
  { step: "02", title: "Matchen", desc: "Unser Algorithmus findet die besten Boote und Händler für Ihre Konfiguration." },
  { step: "03", title: "Angebot erhalten", desc: "Verifizierte Händler senden Ihnen individuelle Angebote direkt zu." },
];

export default function HomePage() {
  return (
    <>
      <Navbar />

      {/* ── HERO ─────────────────────────────────────── */}
      <section className="relative min-h-screen overflow-hidden bg-slate-900">
        <div className="absolute inset-0">
          <img
            src="https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=1920&h=1080&fit=crop"
            alt="Yacht auf dem Meer"
            className="h-full w-full object-cover opacity-40"
          />
          <div className="absolute inset-0 bg-gradient-to-b from-slate-900/60 via-slate-900/40 to-slate-900" />
        </div>

        <div className="relative mx-auto flex min-h-screen max-w-7xl flex-col items-center justify-center px-4 text-center">
          <div className="animate-fade-in">
            <span className="mb-6 inline-block rounded-full border border-sky-400/30 bg-sky-400/10 px-4 py-1.5 text-sm font-medium text-sky-300">
              Die Nr. 1 Plattform für Bootskonfiguration
            </span>
            <h1 className="mx-auto max-w-4xl text-5xl font-extrabold leading-tight tracking-tight text-white sm:text-6xl lg:text-7xl">
              Finden Sie Ihr{" "}
              <span className="bg-gradient-to-r from-sky-400 to-blue-500 bg-clip-text text-transparent">
                Traumboot
              </span>
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-slate-300 sm:text-xl">
              Konfigurieren Sie Ihr Wunschboot, vergleichen Sie Angebote und lassen Sie sich
              von verifizierten Händlern beraten — alles auf einer Plattform.
            </p>
          </div>

          <div className="mt-10 flex flex-col gap-4 sm:flex-row animate-slide-up">
            <Link href="/configurator" className="inline-flex items-center justify-center rounded-xl bg-sky-500 px-8 py-4 text-base font-semibold text-white shadow-lg shadow-sky-500/25 transition-all hover:bg-sky-600 hover:shadow-xl hover:shadow-sky-500/30 active:scale-[0.98]">
              Boot konfigurieren
              <svg className="ml-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M17 8l4 4m0 0l-4 4m4-4H3" />
              </svg>
            </Link>
            <Link href="/boats" className="inline-flex items-center justify-center rounded-xl border border-white/20 bg-white/5 px-8 py-4 text-base font-semibold text-white backdrop-blur-sm transition-all hover:bg-white/10 active:scale-[0.98]">
              Boote entdecken
            </Link>
          </div>

          {/* Search Bar */}
          <div className="mt-16 w-full max-w-3xl animate-slide-up">
            <div className="flex flex-col gap-2 rounded-2xl bg-white/10 p-2 backdrop-blur-xl sm:flex-row">
              <select className="flex-1 rounded-xl bg-white/10 px-4 py-3 text-sm text-white placeholder-slate-400 outline-none">
                <option value="" className="text-slate-900">Bootstyp wählen</option>
                {CATEGORIES.map((c) => (
                  <option key={c.key} value={c.key} className="text-slate-900">{c.label}</option>
                ))}
              </select>
              <select className="flex-1 rounded-xl bg-white/10 px-4 py-3 text-sm text-white outline-none">
                <option value="" className="text-slate-900">Budget</option>
                <option value="50000" className="text-slate-900">Bis 50.000 €</option>
                <option value="150000" className="text-slate-900">Bis 150.000 €</option>
                <option value="500000" className="text-slate-900">Bis 500.000 €</option>
                <option value="1000000" className="text-slate-900">Bis 1.000.000 €</option>
                <option value="999999999" className="text-slate-900">Über 1.000.000 €</option>
              </select>
              <button className="rounded-xl bg-sky-500 px-8 py-3 text-sm font-semibold text-white transition hover:bg-sky-600">
                Suchen
              </button>
            </div>
          </div>
        </div>

        {/* Scroll Indicator */}
        <div className="absolute bottom-8 left-1/2 -translate-x-1/2 animate-bounce">
          <svg className="h-6 w-6 text-white/50" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 14l-7 7m0 0l-7-7m7 7V3" />
          </svg>
        </div>
      </section>

      {/* ── STATS ────────────────────────────────────── */}
      <section className="border-b border-slate-200 bg-white">
        <div className="mx-auto grid max-w-7xl grid-cols-2 gap-8 px-4 py-16 sm:px-6 lg:grid-cols-4 lg:px-8">
          {STATS.map((stat) => (
            <div key={stat.label} className="text-center">
              <p className="text-3xl font-extrabold text-slate-900 sm:text-4xl">{stat.value}</p>
              <p className="mt-1 text-sm font-medium text-slate-500">{stat.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── HOW IT WORKS ─────────────────────────────── */}
      <section className="bg-slate-50 py-24">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <span className="text-sm font-semibold uppercase tracking-wider text-sky-600">So funktioniert&apos;s</span>
            <h2 className="section-title mt-2">In 3 Schritten zum Traumboot</h2>
          </div>

          <div className="mt-16 grid gap-8 sm:grid-cols-3">
            {STEPS.map((s) => (
              <div key={s.step} className="relative rounded-2xl bg-white p-8 shadow-sm">
                <span className="text-5xl font-extrabold text-sky-100">{s.step}</span>
                <h3 className="mt-4 text-xl font-bold text-slate-900">{s.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-500">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CATEGORIES ───────────────────────────────── */}
      <section className="bg-white py-24">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <span className="text-sm font-semibold uppercase tracking-wider text-sky-600">Kategorien</span>
            <h2 className="section-title mt-2">Entdecken Sie alle Bootstypen</h2>
          </div>

          <div className="mt-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {CATEGORIES.map((cat) => (
              <Link
                key={cat.key}
                href={`/boats?category=${cat.key}`}
                className="group relative overflow-hidden rounded-2xl"
              >
                <div className="aspect-[4/3]">
                  <img
                    src={cat.img}
                    alt={cat.label}
                    className="h-full w-full object-cover transition-transform duration-700 group-hover:scale-110"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-slate-900/80 via-slate-900/20 to-transparent" />
                </div>
                <div className="absolute bottom-0 left-0 right-0 p-6">
                  <h3 className="text-2xl font-bold text-white">{cat.label}</h3>
                  <p className="mt-1 flex items-center text-sm text-sky-300 transition group-hover:translate-x-1">
                    Jetzt entdecken
                    <svg className="ml-1 h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M17 8l4 4m0 0l-4 4m4-4H3" />
                    </svg>
                  </p>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA SECTION ──────────────────────────────── */}
      <section className="relative overflow-hidden bg-sky-600 py-24">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0zNiAxOGMzLjMxNCAwIDYtMi42ODYgNi02cy0yLjY4Ni02LTYtNi02IDIuNjg2LTYgNiAyLjY4NiA2IDYgNnptMCAyYy00LjQxOCAwLTgtMy41ODItOC04czMuNTgyLTggOC04IDggMy41ODIgOCA4LTMuNTgyIDgtOCA4eiIgZmlsbD0iI2ZmZiIgZmlsbC1vcGFjaXR5PSIuMDUiLz48L2c+PC9zdmc+')] opacity-30" />
        <div className="relative mx-auto max-w-4xl px-4 text-center">
          <h2 className="text-3xl font-extrabold text-white sm:text-5xl">
            Bereit, Ihr Traumboot zu finden?
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-lg text-sky-100">
            Nutzen Sie unseren intelligenten Konfigurator und erhalten Sie innerhalb von
            24 Stunden individuelle Angebote.
          </p>
          <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
            <Link href="/configurator" className="inline-flex items-center rounded-xl bg-white px-8 py-4 text-base font-semibold text-sky-600 shadow-lg transition hover:bg-sky-50 active:scale-[0.98]">
              Jetzt konfigurieren
            </Link>
            <Link href="/dealer/login" className="inline-flex items-center rounded-xl border border-white/30 px-8 py-4 text-base font-semibold text-white transition hover:bg-white/10 active:scale-[0.98]">
              Sind Sie Händler?
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}
