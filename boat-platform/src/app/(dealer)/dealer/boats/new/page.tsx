"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import DealerSidebar from "@/components/dealer/DealerSidebar";

const CATEGORIES = [
  { key: "YACHT", label: "Yacht" }, { key: "SPORTBOAT", label: "Sportboot" },
  { key: "SAILBOAT", label: "Segelboot" }, { key: "CATAMARAN", label: "Katamaran" },
  { key: "JETSKI", label: "Jetski" }, { key: "PONTOON", label: "Pontonboot" },
  { key: "FISHING", label: "Angelboot" }, { key: "HOUSEBOAT", label: "Hausboot" },
];

export default function NewBoatPage() {
  const { data: session, status: authStatus } = useSession();
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [form, setForm] = useState({
    name: "", brand: "", model: "", year: new Date().getFullYear(),
    basePrice: 0, category: "SPORTBOAT", lengthM: 0, beamM: 0,
    engineType: "", engineBrand: "", maxPowerHP: 0, fuelType: "DIESEL",
    cabins: 0, berths: 0, description: "", location: "",
    hasKitchen: false, hasSoundSystem: false, hasSolarPanel: false, hasSmartSystem: false,
  });

  useEffect(() => {
    if (authStatus === "unauthenticated") router.push("/dealer/login");
  }, [authStatus, router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");

    const payload = {
      ...form,
      basePrice: Number(form.basePrice),
      lengthM: Number(form.lengthM),
      beamM: Number(form.beamM) || undefined,
      maxPowerHP: Number(form.maxPowerHP) || undefined,
      cabins: Number(form.cabins),
      berths: Number(form.berths),
    };

    const res = await fetch("/api/boats", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    setSaving(false);
    if (res.ok) {
      router.push("/dealer/boats");
    } else {
      const data = await res.json();
      setError(typeof data.error === "string" ? data.error : "Fehler beim Speichern");
    }
  }

  if (!session) return null;

  const set = (key: string, value: unknown) => setForm((f) => ({ ...f, [key]: value }));

  return (
    <div className="flex min-h-screen bg-slate-50">
      <DealerSidebar companyName={session.user.companyName ?? session.user.name} />

      <main className="flex-1 pl-64">
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Neues Boot hinzufügen</h1>
        </div>

        <form onSubmit={handleSubmit} className="mx-auto max-w-3xl p-8 space-y-8">
          {/* Basic Info */}
          <div className="card p-6 space-y-4">
            <h2 className="text-lg font-bold text-slate-900">Grunddaten</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Bootsname *</label>
                <input required value={form.name} onChange={(e) => set("name", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Kategorie *</label>
                <select value={form.category} onChange={(e) => set("category", e.target.value)} className="select">
                  {CATEGORIES.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Marke *</label>
                <input required value={form.brand} onChange={(e) => set("brand", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Modell *</label>
                <input required value={form.model} onChange={(e) => set("model", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Baujahr *</label>
                <input required type="number" value={form.year} onChange={(e) => set("year", parseInt(e.target.value))} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Preis (€) *</label>
                <input required type="number" value={form.basePrice || ""} onChange={(e) => set("basePrice", e.target.value)} className="input" />
              </div>
            </div>
          </div>

          {/* Specs */}
          <div className="card p-6 space-y-4">
            <h2 className="text-lg font-bold text-slate-900">Spezifikationen</h2>
            <div className="grid gap-4 sm:grid-cols-3">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Länge (m) *</label>
                <input required type="number" step="0.1" value={form.lengthM || ""} onChange={(e) => set("lengthM", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Breite (m)</label>
                <input type="number" step="0.1" value={form.beamM || ""} onChange={(e) => set("beamM", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Leistung (PS)</label>
                <input type="number" value={form.maxPowerHP || ""} onChange={(e) => set("maxPowerHP", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Motortyp</label>
                <input value={form.engineType} onChange={(e) => set("engineType", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Kabinen</label>
                <input type="number" value={form.cabins} onChange={(e) => set("cabins", e.target.value)} className="input" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Schlafplätze</label>
                <input type="number" value={form.berths} onChange={(e) => set("berths", e.target.value)} className="input" />
              </div>
            </div>
          </div>

          {/* Features */}
          <div className="card p-6 space-y-4">
            <h2 className="text-lg font-bold text-slate-900">Ausstattung</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                { key: "hasKitchen", label: "Küche / Pantry" },
                { key: "hasSoundSystem", label: "Soundsystem" },
                { key: "hasSolarPanel", label: "Solaranlage" },
                { key: "hasSmartSystem", label: "Smart-Systeme" },
              ].map((f) => (
                <label key={f.key} className="flex items-center gap-3 rounded-xl border border-slate-200 p-3 cursor-pointer hover:bg-slate-50 transition">
                  <input
                    type="checkbox"
                    checked={form[f.key as keyof typeof form] as boolean}
                    onChange={(e) => set(f.key, e.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500"
                  />
                  <span className="text-sm font-medium text-slate-700">{f.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Description */}
          <div className="card p-6 space-y-4">
            <h2 className="text-lg font-bold text-slate-900">Beschreibung & Standort</h2>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Standort</label>
              <input value={form.location} onChange={(e) => set("location", e.target.value)} className="input" placeholder="z.B. Hamburg, Deutschland" />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Beschreibung</label>
              <textarea rows={5} value={form.description} onChange={(e) => set("description", e.target.value)} className="input" placeholder="Beschreiben Sie Ihr Boot..." />
            </div>
          </div>

          {error && (
            <div className="rounded-lg bg-red-50 border border-red-100 p-4 text-sm text-red-700">{error}</div>
          )}

          <div className="flex justify-end gap-3">
            <button type="button" onClick={() => router.back()} className="btn-secondary">Abbrechen</button>
            <button type="submit" disabled={saving} className="btn-primary">
              {saving ? "Speichern..." : "Boot veröffentlichen"}
            </button>
          </div>
        </form>
      </main>
    </div>
  );
}
