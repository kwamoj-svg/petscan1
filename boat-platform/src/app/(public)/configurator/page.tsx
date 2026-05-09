"use client";

import { useState } from "react";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import BoatCard from "@/components/ui/BoatCard";

const STEPS = ["Bootstyp", "Details", "Ausstattung", "Einsatz", "Ergebnis", "Kontakt"];

const BOAT_TYPES = [
  { key: "YACHT", label: "Yacht", desc: "Luxuriöse Motoryachten für höchste Ansprüche", icon: "🛥️" },
  { key: "SPORTBOAT", label: "Sportboot", desc: "Schnelle Boote für Adrenalin auf dem Wasser", icon: "🚤" },
  { key: "SAILBOAT", label: "Segelboot", desc: "Klassisches Segeln unter Wind", icon: "⛵" },
  { key: "CATAMARAN", label: "Katamaran", desc: "Stabile Mehrrumpfboote für Komfort", icon: "🚢" },
  { key: "JETSKI", label: "Jetski", desc: "Kompakt und wendig für Wassersport", icon: "🏄" },
  { key: "FISHING", label: "Angelboot", desc: "Spezialisiert auf den perfekten Fang", icon: "🎣" },
];

const BUDGETS = [
  { value: 25000, label: "Bis 25.000 €" },
  { value: 50000, label: "Bis 50.000 €" },
  { value: 100000, label: "Bis 100.000 €" },
  { value: 250000, label: "Bis 250.000 €" },
  { value: 500000, label: "Bis 500.000 €" },
  { value: 1000000, label: "Bis 1.000.000 €" },
  { value: 9999999, label: "Über 1.000.000 €" },
];

const LENGTHS = [
  { min: 3, max: 6, label: "3 – 6 m" },
  { min: 6, max: 10, label: "6 – 10 m" },
  { min: 10, max: 15, label: "10 – 15 m" },
  { min: 15, max: 25, label: "15 – 25 m" },
  { min: 25, max: 100, label: "25+ m" },
];

const ENGINES = ["Außenborder", "Innenborder", "Diesel", "Elektro", "Hybrid", "Segel"];

const FEATURES = [
  { key: "kitchen", label: "Küche / Pantry", icon: "🍳" },
  { key: "soundSystem", label: "Soundsystem", icon: "🔊" },
  { key: "solarPanel", label: "Solaranlage", icon: "☀️" },
  { key: "smartSystem", label: "Smart-Systeme", icon: "📱" },
];

const LUXURY_PACKAGES = [
  { key: "comfort", label: "Komfort-Paket", desc: "Premium-Polster, LED-Beleuchtung, Bugstrahlruder" },
  { key: "adventure", label: "Abenteuer-Paket", desc: "Davits, Beiboot, Tauchplattform, Schnorchel-Set" },
  { key: "tech", label: "Tech-Paket", desc: "Chartplotter, Radar, AIS, Autopilot" },
];

const USE_CASES = [
  { key: "LEISURE", label: "Freizeit", desc: "Tagesausflüge & Wochenenden", icon: "🌊" },
  { key: "CHARTER", label: "Charter", desc: "Vermietung & Chartergeschäft", icon: "💼" },
  { key: "LUXURY", label: "Luxusreisen", desc: "Langstrecken & Luxus-Cruising", icon: "✨" },
  { key: "FISHING", label: "Angeln", desc: "Sportfischen & Angel-Trips", icon: "🎣" },
  { key: "WATERSPORT", label: "Wassersport", desc: "Wakeboard, Ski, Tubing", icon: "🏄" },
];

interface ConfigState {
  category: string;
  budget: number;
  minLength: number;
  maxLength: number;
  engineType: string;
  cabins: number;
  brand: string;
  features: Record<string, boolean>;
  luxuryPackages: string[];
  useCase: string;
}

interface Recommendation {
  id: string;
  name: string;
  brand: string;
  model: string;
  year: number;
  basePrice: number;
  category: string;
  lengthM: number;
  cabins: number;
  images: { url: string }[];
  dealer: { companyName: string; city: string };
  isFeatured: boolean;
}

export default function ConfiguratorPage() {
  const [step, setStep] = useState(0);
  const [config, setConfig] = useState<ConfigState>({
    category: "",
    budget: 0,
    minLength: 0,
    maxLength: 100,
    engineType: "",
    cabins: 0,
    brand: "",
    features: {},
    luxuryPackages: [],
    useCase: "",
  });
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [contact, setContact] = useState({ customerName: "", customerEmail: "", customerPhone: "", message: "" });
  const [submitted, setSubmitted] = useState(false);
  const [loadingRecs, setLoadingRecs] = useState(false);

  function nextStep() {
    if (step === 3) {
      fetchRecommendations();
    }
    setStep((s) => Math.min(s + 1, STEPS.length - 1));
  }

  function prevStep() {
    setStep((s) => Math.max(s - 1, 0));
  }

  async function fetchRecommendations() {
    setLoadingRecs(true);
    try {
      const res = await fetch("/api/configurator", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
      });
      const data = await res.json();
      setRecommendations(data.recommendations ?? []);
    } catch {
      // Will show empty results
    }
    setLoadingRecs(false);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetch("/api/leads", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...contact,
        configData: config,
        budget: config.budget || undefined,
        source: "CONFIGURATOR",
      }),
    });
    if (res.ok) setSubmitted(true);
  }

  const progress = ((step + 1) / STEPS.length) * 100;

  if (submitted) {
    return (
      <>
        <Navbar />
        <main className="flex min-h-screen items-center justify-center pt-16">
          <div className="mx-auto max-w-md animate-fade-in text-center">
            <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-emerald-100">
              <svg className="h-10 w-10 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h2 className="mt-6 text-3xl font-extrabold text-slate-900">Anfrage gesendet!</h2>
            <p className="mt-3 text-slate-500">
              Passende Händler haben Ihre Konfiguration erhalten und werden sich
              innerhalb von 24 Stunden bei Ihnen melden.
            </p>
            <a href="/" className="btn-primary mt-8 inline-flex">Zur Startseite</a>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      <Navbar />
      <main className="min-h-screen bg-slate-50 pt-16">
        {/* Progress */}
        <div className="bg-white border-b border-slate-200">
          <div className="mx-auto max-w-4xl px-4 py-6">
            <div className="flex items-center justify-between mb-3">
              {STEPS.map((s, i) => (
                <button
                  key={s}
                  onClick={() => i <= step && setStep(i)}
                  className={`text-xs font-medium transition ${
                    i <= step ? "text-sky-600" : "text-slate-400"
                  } ${i === step ? "font-bold" : ""}`}
                >
                  <span className="hidden sm:inline">{s}</span>
                  <span className="sm:hidden">{i + 1}</span>
                </button>
              ))}
            </div>
            <div className="h-1.5 w-full rounded-full bg-slate-100">
              <div
                className="h-1.5 rounded-full bg-sky-500 transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        </div>

        <div className="mx-auto max-w-4xl px-4 py-12">
          {/* Step 0: Bootstyp */}
          {step === 0 && (
            <div className="animate-fade-in">
              <h2 className="text-3xl font-extrabold text-slate-900">Welchen Bootstyp suchen Sie?</h2>
              <p className="mt-2 text-slate-500">Wählen Sie die Kategorie, die am besten zu Ihnen passt.</p>
              <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {BOAT_TYPES.map((type) => (
                  <button
                    key={type.key}
                    onClick={() => setConfig((c) => ({ ...c, category: type.key }))}
                    className={`rounded-2xl border-2 p-6 text-left transition-all ${
                      config.category === type.key
                        ? "border-sky-500 bg-sky-50 ring-2 ring-sky-500/20"
                        : "border-slate-200 bg-white hover:border-slate-300 hover:shadow-sm"
                    }`}
                  >
                    <span className="text-3xl">{type.icon}</span>
                    <h3 className="mt-3 text-lg font-bold text-slate-900">{type.label}</h3>
                    <p className="mt-1 text-sm text-slate-500">{type.desc}</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 1: Details */}
          {step === 1 && (
            <div className="animate-fade-in space-y-10">
              <div>
                <h2 className="text-3xl font-extrabold text-slate-900">Budget & Größe</h2>
                <p className="mt-2 text-slate-500">Definieren Sie Ihren Rahmen.</p>
              </div>

              <div>
                <label className="text-sm font-semibold text-slate-700">Budget</label>
                <div className="mt-3 grid gap-2 sm:grid-cols-3 lg:grid-cols-4">
                  {BUDGETS.map((b) => (
                    <button
                      key={b.value}
                      onClick={() => setConfig((c) => ({ ...c, budget: b.value }))}
                      className={`rounded-xl border px-4 py-3 text-sm font-medium transition ${
                        config.budget === b.value
                          ? "border-sky-500 bg-sky-50 text-sky-700"
                          : "border-slate-200 text-slate-600 hover:border-slate-300"
                      }`}
                    >
                      {b.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-sm font-semibold text-slate-700">Bootslänge</label>
                <div className="mt-3 grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
                  {LENGTHS.map((l) => (
                    <button
                      key={l.label}
                      onClick={() => setConfig((c) => ({ ...c, minLength: l.min, maxLength: l.max }))}
                      className={`rounded-xl border px-4 py-3 text-sm font-medium transition ${
                        config.minLength === l.min
                          ? "border-sky-500 bg-sky-50 text-sky-700"
                          : "border-slate-200 text-slate-600 hover:border-slate-300"
                      }`}
                    >
                      {l.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-sm font-semibold text-slate-700">Motorisierung</label>
                <div className="mt-3 grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
                  {ENGINES.map((eng) => (
                    <button
                      key={eng}
                      onClick={() => setConfig((c) => ({ ...c, engineType: eng }))}
                      className={`rounded-xl border px-4 py-3 text-sm font-medium transition ${
                        config.engineType === eng
                          ? "border-sky-500 bg-sky-50 text-sky-700"
                          : "border-slate-200 text-slate-600 hover:border-slate-300"
                      }`}
                    >
                      {eng}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-sm font-semibold text-slate-700">Kabinen</label>
                <div className="mt-3 flex gap-2">
                  {[0, 1, 2, 3, 4, 5, 6].map((n) => (
                    <button
                      key={n}
                      onClick={() => setConfig((c) => ({ ...c, cabins: n }))}
                      className={`flex h-12 w-12 items-center justify-center rounded-xl border text-sm font-semibold transition ${
                        config.cabins === n
                          ? "border-sky-500 bg-sky-50 text-sky-700"
                          : "border-slate-200 text-slate-600 hover:border-slate-300"
                      }`}
                    >
                      {n === 0 ? "–" : n}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 2: Ausstattung */}
          {step === 2 && (
            <div className="animate-fade-in space-y-10">
              <div>
                <h2 className="text-3xl font-extrabold text-slate-900">Ausstattung</h2>
                <p className="mt-2 text-slate-500">Welche Features sind Ihnen wichtig?</p>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                {FEATURES.map((f) => (
                  <button
                    key={f.key}
                    onClick={() =>
                      setConfig((c) => ({
                        ...c,
                        features: { ...c.features, [f.key]: !c.features[f.key] },
                      }))
                    }
                    className={`flex items-center gap-4 rounded-2xl border-2 p-5 text-left transition-all ${
                      config.features[f.key]
                        ? "border-sky-500 bg-sky-50"
                        : "border-slate-200 bg-white hover:border-slate-300"
                    }`}
                  >
                    <span className="text-2xl">{f.icon}</span>
                    <div>
                      <p className="font-semibold text-slate-900">{f.label}</p>
                    </div>
                    <div className="ml-auto">
                      <div className={`flex h-6 w-6 items-center justify-center rounded-full transition ${
                        config.features[f.key] ? "bg-sky-500" : "border-2 border-slate-300"
                      }`}>
                        {config.features[f.key] && (
                          <svg className="h-3.5 w-3.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              <div>
                <h3 className="text-lg font-bold text-slate-900">Luxuspakete</h3>
                <div className="mt-4 grid gap-4 sm:grid-cols-3">
                  {LUXURY_PACKAGES.map((pkg) => (
                    <button
                      key={pkg.key}
                      onClick={() =>
                        setConfig((c) => ({
                          ...c,
                          luxuryPackages: c.luxuryPackages.includes(pkg.key)
                            ? c.luxuryPackages.filter((p) => p !== pkg.key)
                            : [...c.luxuryPackages, pkg.key],
                        }))
                      }
                      className={`rounded-2xl border-2 p-5 text-left transition-all ${
                        config.luxuryPackages.includes(pkg.key)
                          ? "border-amber-400 bg-amber-50"
                          : "border-slate-200 bg-white hover:border-slate-300"
                      }`}
                    >
                      <h4 className="font-bold text-slate-900">{pkg.label}</h4>
                      <p className="mt-1 text-sm text-slate-500">{pkg.desc}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Einsatzgebiet */}
          {step === 3 && (
            <div className="animate-fade-in">
              <h2 className="text-3xl font-extrabold text-slate-900">Einsatzgebiet</h2>
              <p className="mt-2 text-slate-500">Wie möchten Sie Ihr Boot hauptsächlich nutzen?</p>
              <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {USE_CASES.map((uc) => (
                  <button
                    key={uc.key}
                    onClick={() => setConfig((c) => ({ ...c, useCase: uc.key }))}
                    className={`rounded-2xl border-2 p-6 text-left transition-all ${
                      config.useCase === uc.key
                        ? "border-sky-500 bg-sky-50 ring-2 ring-sky-500/20"
                        : "border-slate-200 bg-white hover:border-slate-300"
                    }`}
                  >
                    <span className="text-3xl">{uc.icon}</span>
                    <h3 className="mt-3 text-lg font-bold text-slate-900">{uc.label}</h3>
                    <p className="mt-1 text-sm text-slate-500">{uc.desc}</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 4: Ergebnis / Empfehlungen */}
          {step === 4 && (
            <div className="animate-fade-in">
              <h2 className="text-3xl font-extrabold text-slate-900">Unsere Empfehlungen</h2>
              <p className="mt-2 text-slate-500">Basierend auf Ihrer Konfiguration haben wir folgende Boote gefunden.</p>

              <div className="mt-4 rounded-xl bg-sky-50 border border-sky-100 p-4">
                <p className="text-sm text-sky-700">
                  <strong>Ihre Auswahl:</strong>{" "}
                  {BOAT_TYPES.find((t) => t.key === config.category)?.label ?? "–"} &middot;{" "}
                  {config.budget > 0 ? `bis ${config.budget.toLocaleString("de-DE")} €` : "Jedes Budget"} &middot;{" "}
                  {config.minLength > 0 ? `${config.minLength}–${config.maxLength} m` : "Jede Größe"}
                </p>
              </div>

              {loadingRecs ? (
                <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="card animate-pulse overflow-hidden">
                      <div className="aspect-[4/3] bg-slate-200" />
                      <div className="p-5 space-y-3">
                        <div className="h-5 w-3/4 rounded bg-slate-200" />
                        <div className="h-4 w-1/2 rounded bg-slate-100" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : recommendations.length > 0 ? (
                <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                  {recommendations.map((boat) => (
                    <BoatCard
                      key={boat.id}
                      id={boat.id}
                      name={boat.name}
                      brand={boat.brand}
                      model={boat.model}
                      year={boat.year}
                      basePrice={boat.basePrice}
                      category={boat.category}
                      lengthM={boat.lengthM}
                      cabins={boat.cabins}
                      imageUrl={boat.images?.[0]?.url}
                      dealerName={boat.dealer?.companyName}
                      isFeatured={boat.isFeatured}
                    />
                  ))}
                </div>
              ) : (
                <div className="mt-8 rounded-2xl border-2 border-dashed border-slate-200 p-12 text-center">
                  <p className="text-lg font-semibold text-slate-700">Noch keine passenden Boote in der Datenbank</p>
                  <p className="mt-2 text-sm text-slate-500">
                    Senden Sie trotzdem Ihre Anfrage — passende Händler werden sich mit individuellen Angeboten bei Ihnen melden.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 5: Kontakt */}
          {step === 5 && (
            <div className="animate-fade-in">
              <h2 className="text-3xl font-extrabold text-slate-900">Fast geschafft!</h2>
              <p className="mt-2 text-slate-500">
                Hinterlassen Sie Ihre Kontaktdaten und erhalten Sie individuelle Angebote.
              </p>

              <form onSubmit={handleSubmit} className="mt-8 mx-auto max-w-lg space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Name *</label>
                  <input required value={contact.customerName} onChange={(e) => setContact((f) => ({ ...f, customerName: e.target.value }))} className="input" placeholder="Max Mustermann" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">E-Mail *</label>
                  <input required type="email" value={contact.customerEmail} onChange={(e) => setContact((f) => ({ ...f, customerEmail: e.target.value }))} className="input" placeholder="max@example.com" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Telefon</label>
                  <input value={contact.customerPhone} onChange={(e) => setContact((f) => ({ ...f, customerPhone: e.target.value }))} className="input" placeholder="+49 170 1234567" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Nachricht</label>
                  <textarea rows={4} value={contact.message} onChange={(e) => setContact((f) => ({ ...f, message: e.target.value }))} className="input" placeholder="Haben Sie besondere Wünsche oder Fragen?" />
                </div>
                <button type="submit" className="btn-primary w-full py-4 text-base">
                  Unverbindliche Anfrage senden
                </button>
                <p className="text-center text-xs text-slate-400">
                  Ihre Daten werden nur an passende Händler weitergeleitet.
                </p>
              </form>
            </div>
          )}

          {/* Navigation Buttons */}
          <div className="mt-12 flex items-center justify-between">
            {step > 0 ? (
              <button onClick={prevStep} className="btn-secondary">
                <svg className="mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
                </svg>
                Zurück
              </button>
            ) : (
              <div />
            )}
            {step < STEPS.length - 1 && (
              <button
                onClick={nextStep}
                disabled={step === 0 && !config.category}
                className="btn-primary"
              >
                Weiter
                <svg className="ml-2 h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
              </button>
            )}
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
