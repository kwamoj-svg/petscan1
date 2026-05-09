"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import Link from "next/link";
import DealerSidebar from "@/components/dealer/DealerSidebar";

interface Boat {
  id: string;
  name: string;
  brand: string;
  model: string;
  year: number;
  basePrice: number;
  category: string;
  lengthM: number;
  isActive: boolean;
  viewCount: number;
  _count: { leads: number };
  images: { url: string }[];
}

const CATEGORY_LABELS: Record<string, string> = {
  YACHT: "Yacht", SPORTBOAT: "Sportboot", SAILBOAT: "Segelboot", CATAMARAN: "Katamaran",
  JETSKI: "Jetski", PONTOON: "Pontonboot", FISHING: "Angelboot", HOUSEBOAT: "Hausboot",
};

export default function DealerBoatsPage() {
  const { data: session, status: authStatus } = useSession();
  const router = useRouter();
  const [boats, setBoats] = useState<Boat[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authStatus === "unauthenticated") router.push("/dealer/login");
  }, [authStatus, router]);

  useEffect(() => {
    if (authStatus !== "authenticated" || !session?.user?.dealerId) return;
    fetch(`/api/boats?dealerId=${session.user.dealerId}&limit=100`)
      .then((r) => r.json())
      .then((data) => {
        setBoats(data.boats ?? []);
        setLoading(false);
      });
  }, [authStatus, session]);

  if (authStatus === "loading" || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-pulse text-slate-400">Laden...</div>
      </div>
    );
  }

  if (!session) return null;

  return (
    <div className="flex min-h-screen bg-slate-50">
      <DealerSidebar companyName={session.user.companyName ?? session.user.name} />

      <main className="flex-1 pl-64">
        <div className="flex items-center justify-between border-b border-slate-200 bg-white px-8 py-6">
          <div>
            <h1 className="text-2xl font-extrabold text-slate-900">Meine Boote</h1>
            <p className="text-sm text-slate-500">{boats.length} Boote gelistet</p>
          </div>
          <Link href="/dealer/boats/new" className="btn-primary">
            <svg className="mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Boot hinzufügen
          </Link>
        </div>

        <div className="p-8">
          {boats.length === 0 ? (
            <div className="card p-16 text-center">
              <svg className="mx-auto h-12 w-12 text-slate-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4" />
              </svg>
              <h3 className="mt-4 text-lg font-semibold text-slate-700">Keine Boote vorhanden</h3>
              <p className="mt-2 text-sm text-slate-500">Fügen Sie Ihr erstes Boot hinzu, um Leads zu erhalten.</p>
              <Link href="/dealer/boats/new" className="btn-primary mt-6 inline-flex">Boot hinzufügen</Link>
            </div>
          ) : (
            <div className="grid gap-4">
              {boats.map((boat) => (
                <div key={boat.id} className="card flex items-center gap-6 p-4">
                  <div className="h-20 w-28 shrink-0 overflow-hidden rounded-xl bg-slate-100">
                    <img
                      src={boat.images?.[0]?.url ?? "https://images.unsplash.com/photo-1544551763-46a013bb70d5?w=200&h=150&fit=crop"}
                      alt={boat.name}
                      className="h-full w-full object-cover"
                    />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-bold text-slate-900 truncate">{boat.name}</h3>
                      <span className={`badge ${boat.isActive ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-500"}`}>
                        {boat.isActive ? "Aktiv" : "Inaktiv"}
                      </span>
                    </div>
                    <p className="text-sm text-slate-500">
                      {boat.brand} {boat.model} · {boat.year} · {CATEGORY_LABELS[boat.category] ?? boat.category}
                    </p>
                    <div className="mt-1 flex items-center gap-4 text-xs text-slate-400">
                      <span>{boat.lengthM} m</span>
                      <span>{boat.viewCount} Aufrufe</span>
                      <span>{boat._count?.leads ?? 0} Leads</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-lg font-bold text-sky-600">
                      {boat.basePrice.toLocaleString("de-DE")} €
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
