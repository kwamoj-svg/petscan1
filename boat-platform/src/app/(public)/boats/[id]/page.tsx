"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";

interface BoatDetail {
  id: string;
  name: string;
  brand: string;
  model: string;
  year: number;
  condition: string;
  basePrice: number;
  category: string;
  lengthM: number;
  beamM: number | null;
  weightKg: number | null;
  engineType: string | null;
  engineBrand: string | null;
  maxPowerHP: number | null;
  fuelType: string | null;
  cabins: number;
  berths: number;
  heads: number;
  hasKitchen: boolean;
  hasSoundSystem: boolean;
  hasSolarPanel: boolean;
  hasSmartSystem: boolean;
  description: string | null;
  location: string | null;
  images: { url: string; alt: string | null }[];
  dealer: { companyName: string; city: string };
  configs: { id: string; group: string; name: string; price: number; isDefault: boolean }[];
}

export default function BoatDetailPage() {
  const { id } = useParams();
  const [boat, setBoat] = useState<BoatDetail | null>(null);
  const [showContact, setShowContact] = useState(false);
  const [form, setForm] = useState({ customerName: "", customerEmail: "", customerPhone: "", message: "" });
  const [sent, setSent] = useState(false);

  useEffect(() => {
    fetch(`/api/boats?limit=100`).then((r) => r.json()).then((data) => {
      const found = data.boats?.find((b: BoatDetail) => b.id === id);
      if (found) setBoat(found);
    });
  }, [id]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!boat) return;
    const res = await fetch("/api/leads", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ boatId: boat.id, ...form, source: "BOAT_LISTING" }),
    });
    if (res.ok) setSent(true);
  }

  if (!boat) {
    return (
      <>
        <Navbar />
        <main className="flex min-h-screen items-center justify-center pt-16">
          <div className="animate-pulse text-slate-400">Laden...</div>
        </main>
      </>
    );
  }

  const PLACEHOLDER = "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=800&h=500&fit=crop";
  const mainImage = boat.images?.[0]?.url ?? PLACEHOLDER;

  const specs = [
    { label: "Länge", value: `${boat.lengthM} m` },
    boat.beamM && { label: "Breite", value: `${boat.beamM} m` },
    boat.weightKg && { label: "Gewicht", value: `${boat.weightKg.toLocaleString("de-DE")} kg` },
    boat.engineType && { label: "Motor", value: boat.engineType },
    boat.engineBrand && { label: "Motormarke", value: boat.engineBrand },
    boat.maxPowerHP && { label: "Leistung", value: `${boat.maxPowerHP} PS` },
    boat.fuelType && { label: "Kraftstoff", value: boat.fuelType },
    boat.cabins > 0 && { label: "Kabinen", value: boat.cabins },
    boat.berths > 0 && { label: "Schlafplätze", value: boat.berths },
    boat.heads > 0 && { label: "Nasszellen", value: boat.heads },
  ].filter(Boolean) as { label: string; value: string | number }[];

  const features = [
    boat.hasKitchen && "Küche",
    boat.hasSoundSystem && "Soundsystem",
    boat.hasSolarPanel && "Solaranlage",
    boat.hasSmartSystem && "Smart-Systeme",
  ].filter(Boolean);

  return (
    <>
      <Navbar />
      <main className="min-h-screen pt-16">
        {/* Hero Image */}
        <div className="relative h-[50vh] bg-slate-900">
          <img src={mainImage} alt={boat.name} className="h-full w-full object-cover opacity-80" />
          <div className="absolute inset-0 bg-gradient-to-t from-slate-900/80 to-transparent" />
          <div className="absolute bottom-0 left-0 right-0 p-8">
            <div className="mx-auto max-w-7xl">
              <Link href="/boats" className="mb-4 inline-flex items-center text-sm text-sky-300 hover:text-white transition">
                <svg className="mr-1 h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
                </svg>
                Zurück
              </Link>
              <h1 className="text-4xl font-extrabold text-white">{boat.name}</h1>
              <p className="mt-1 text-lg text-slate-300">
                {boat.brand} {boat.model} &middot; {boat.year} &middot; {boat.condition === "NEW" ? "Neuboot" : "Gebraucht"}
              </p>
            </div>
          </div>
        </div>

        <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
          <div className="grid gap-12 lg:grid-cols-3">
            {/* Left: Details */}
            <div className="lg:col-span-2 space-y-10">
              <div>
                <h2 className="text-2xl font-bold text-slate-900">Spezifikationen</h2>
                <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-3">
                  {specs.map((s) => (
                    <div key={s.label} className="rounded-xl bg-slate-50 p-4">
                      <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{s.label}</p>
                      <p className="mt-1 text-lg font-semibold text-slate-900">{s.value}</p>
                    </div>
                  ))}
                </div>
              </div>

              {features.length > 0 && (
                <div>
                  <h2 className="text-2xl font-bold text-slate-900">Ausstattung</h2>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {features.map((f) => (
                      <span key={f as string} className="badge bg-sky-50 text-sky-700 ring-1 ring-sky-200 px-3 py-1.5 text-sm">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {boat.description && (
                <div>
                  <h2 className="text-2xl font-bold text-slate-900">Beschreibung</h2>
                  <p className="mt-4 leading-relaxed text-slate-600">{boat.description}</p>
                </div>
              )}
            </div>

            {/* Right: Price & Contact */}
            <div className="space-y-6">
              <div className="card p-6 sticky top-24">
                <p className="text-sm font-medium text-slate-500">Preis</p>
                <p className="text-4xl font-extrabold text-slate-900">
                  {boat.basePrice.toLocaleString("de-DE")} €
                </p>
                <p className="mt-1 text-sm text-slate-400">zzgl. Optionen & MwSt.</p>

                <div className="mt-6 rounded-xl bg-slate-50 p-4">
                  <p className="text-sm font-semibold text-slate-700">{boat.dealer.companyName}</p>
                  {boat.dealer.city && <p className="text-sm text-slate-500">{boat.dealer.city}</p>}
                </div>

                {!sent ? (
                  <>
                    {!showContact ? (
                      <button onClick={() => setShowContact(true)} className="btn-primary mt-6 w-full">
                        Händler kontaktieren
                      </button>
                    ) : (
                      <form onSubmit={handleSubmit} className="mt-6 space-y-3">
                        <input required placeholder="Ihr Name" value={form.customerName} onChange={(e) => setForm((f) => ({ ...f, customerName: e.target.value }))} className="input" />
                        <input required type="email" placeholder="E-Mail" value={form.customerEmail} onChange={(e) => setForm((f) => ({ ...f, customerEmail: e.target.value }))} className="input" />
                        <input placeholder="Telefon (optional)" value={form.customerPhone} onChange={(e) => setForm((f) => ({ ...f, customerPhone: e.target.value }))} className="input" />
                        <textarea placeholder="Ihre Nachricht" rows={3} value={form.message} onChange={(e) => setForm((f) => ({ ...f, message: e.target.value }))} className="input" />
                        <button type="submit" className="btn-primary w-full">Anfrage senden</button>
                      </form>
                    )}
                  </>
                ) : (
                  <div className="mt-6 rounded-xl bg-emerald-50 p-4 text-center">
                    <p className="font-semibold text-emerald-700">Anfrage gesendet!</p>
                    <p className="mt-1 text-sm text-emerald-600">Der Händler meldet sich in Kürze.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
