"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import AdminSidebar from "@/components/admin/AdminSidebar";

interface Boat {
  id: string;
  name: string;
  brand: string;
  model: string;
  year: number;
  basePrice: number;
  category: string;
  isActive: boolean;
  isFeatured: boolean;
  viewCount: number;
  dealer: { companyName: string; city: string };
  _count: { leads: number };
}

const CAT_LABELS: Record<string, string> = {
  YACHT: "Yacht", SPORTBOAT: "Sportboot", SAILBOAT: "Segelboot", CATAMARAN: "Katamaran",
  JETSKI: "Jetski", PONTOON: "Pontonboot", FISHING: "Angelboot", HOUSEBOAT: "Hausboot",
};

export default function AdminBoatsPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [boats, setBoats] = useState<Boat[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (status === "unauthenticated") router.push("/admin/login");
    if (status === "authenticated" && session?.user?.role !== "ADMIN") router.push("/");
  }, [status, session, router]);

  useEffect(() => {
    if (status !== "authenticated") return;
    fetch("/api/boats?limit=100").then((r) => r.json()).then((data) => {
      setBoats(data.boats ?? []);
      setTotal(data.total ?? 0);
      setLoading(false);
    });
  }, [status]);

  if (status !== "authenticated" || !session) return null;

  return (
    <div className="flex min-h-screen bg-slate-50">
      <AdminSidebar />
      <main className="flex-1 pl-64">
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Bootsdatenbank</h1>
          <p className="text-sm text-slate-500">{total} Boote insgesamt</p>
        </div>

        <div className="p-8">
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50 text-left">
                  <th className="px-6 py-3 font-semibold text-slate-500">Boot</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Kategorie</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Händler</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Preis</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Views</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Leads</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {boats.map((boat) => (
                  <tr key={boat.id} className="hover:bg-slate-50 transition">
                    <td className="px-6 py-4">
                      <p className="font-semibold text-slate-900">{boat.name}</p>
                      <p className="text-xs text-slate-400">{boat.brand} {boat.model} · {boat.year}</p>
                    </td>
                    <td className="px-6 py-4 text-slate-600">{CAT_LABELS[boat.category] ?? boat.category}</td>
                    <td className="px-6 py-4">
                      <p className="text-slate-700">{boat.dealer.companyName}</p>
                      <p className="text-xs text-slate-400">{boat.dealer.city}</p>
                    </td>
                    <td className="px-6 py-4 font-medium text-slate-700">{boat.basePrice.toLocaleString("de-DE")} €</td>
                    <td className="px-6 py-4 text-slate-500">{boat.viewCount}</td>
                    <td className="px-6 py-4 text-slate-500">{boat._count?.leads ?? 0}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-1">
                        {boat.isFeatured && <span className="badge bg-amber-50 text-amber-700">Featured</span>}
                        <span className={`badge ${boat.isActive ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-600"}`}>
                          {boat.isActive ? "Aktiv" : "Inaktiv"}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {boats.length === 0 && !loading && (
              <div className="py-12 text-center text-slate-500">Keine Boote vorhanden.</div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
