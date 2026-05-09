"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import BoatCard from "@/components/ui/BoatCard";

const CATEGORIES = [
  { key: "", label: "Alle Boote" },
  { key: "YACHT", label: "Yachten" },
  { key: "SPORTBOAT", label: "Sportboote" },
  { key: "SAILBOAT", label: "Segelboote" },
  { key: "CATAMARAN", label: "Katamarane" },
  { key: "JETSKI", label: "Jetskis" },
  { key: "FISHING", label: "Angelboote" },
  { key: "PONTOON", label: "Pontonboote" },
  { key: "HOUSEBOAT", label: "Hausboote" },
];

interface BoatListItem {
  id: string;
  name: string;
  brand: string;
  model: string;
  year: number;
  basePrice: number;
  category: string;
  lengthM: number;
  cabins: number;
  isFeatured: boolean;
  images: { url: string }[];
  dealer: { companyName: string; city: string };
}

export default function BoatsPage() {
  const searchParams = useSearchParams();
  const [boats, setBoats] = useState<BoatListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [category, setCategory] = useState(searchParams.get("category") ?? "");
  const [priceRange, setPriceRange] = useState("");

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (category) params.set("category", category);
    if (priceRange) params.set("maxPrice", priceRange);

    fetch(`/api/boats?${params}`)
      .then((r) => r.json())
      .then((data) => {
        setBoats(data.boats ?? []);
        setTotal(data.total ?? 0);
        setLoading(false);
      });
  }, [category, priceRange]);

  return (
    <>
      <Navbar />
      <main className="min-h-screen pt-16">
        {/* Header */}
        <div className="bg-slate-900 px-4 py-16 text-center">
          <h1 className="text-4xl font-extrabold text-white sm:text-5xl">
            Boote <span className="text-sky-400">entdecken</span>
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-slate-400">
            Durchsuchen Sie unser Angebot von über {total > 0 ? total : "2.500"} Booten
            von verifizierten Händlern.
          </p>
        </div>

        <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
          {/* Filters */}
          <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap gap-2">
              {CATEGORIES.map((c) => (
                <button
                  key={c.key}
                  onClick={() => setCategory(c.key)}
                  className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                    category === c.key
                      ? "bg-sky-600 text-white"
                      : "bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50"
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
            <select
              value={priceRange}
              onChange={(e) => setPriceRange(e.target.value)}
              className="select max-w-[200px]"
            >
              <option value="">Alle Preise</option>
              <option value="50000">Bis 50.000 €</option>
              <option value="150000">Bis 150.000 €</option>
              <option value="500000">Bis 500.000 €</option>
              <option value="1000000">Bis 1.000.000 €</option>
            </select>
          </div>

          {/* Results */}
          {loading ? (
            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="card animate-pulse overflow-hidden">
                  <div className="aspect-[4/3] bg-slate-200" />
                  <div className="p-5 space-y-3">
                    <div className="h-5 w-3/4 rounded bg-slate-200" />
                    <div className="h-4 w-1/2 rounded bg-slate-100" />
                    <div className="h-3 w-2/3 rounded bg-slate-100" />
                  </div>
                </div>
              ))}
            </div>
          ) : boats.length === 0 ? (
            <div className="rounded-2xl border-2 border-dashed border-slate-200 p-16 text-center">
              <svg className="mx-auto h-12 w-12 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4" />
              </svg>
              <h3 className="mt-4 text-lg font-semibold text-slate-700">Keine Boote gefunden</h3>
              <p className="mt-2 text-sm text-slate-500">Versuchen Sie andere Filter oder starten Sie den Konfigurator.</p>
            </div>
          ) : (
            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {boats.map((boat) => (
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
                  dealerCity={boat.dealer?.city}
                  isFeatured={boat.isFeatured}
                />
              ))}
            </div>
          )}
        </div>
      </main>
      <Footer />
    </>
  );
}
