"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import AdminSidebar from "@/components/admin/AdminSidebar";

interface Dealer {
  id: string;
  companyName: string;
  city: string | null;
  country: string;
  tier: string;
  isVerified: boolean;
  isActive: boolean;
  createdAt: string;
  user: { email: string; name: string; isActive: boolean };
  subscription: { plan: string; status: string } | null;
  _count: { boats: number; leads: number };
}

const TIER_BADGE: Record<string, string> = {
  BASIC: "bg-slate-100 text-slate-600",
  PREMIUM: "bg-amber-50 text-amber-700",
  ENTERPRISE: "bg-purple-50 text-purple-700",
};

export default function AdminDealersPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [dealers, setDealers] = useState<Dealer[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (status === "unauthenticated") router.push("/admin/login");
    if (status === "authenticated" && session?.user?.role !== "ADMIN") router.push("/");
  }, [status, session, router]);

  useEffect(() => {
    if (status !== "authenticated") return;
    fetch("/api/dealers").then((r) => r.json()).then((data) => {
      setDealers(Array.isArray(data) ? data : []);
      setLoading(false);
    });
  }, [status]);

  if (status !== "authenticated" || !session) return null;

  return (
    <div className="flex min-h-screen bg-slate-50">
      <AdminSidebar />
      <main className="flex-1 pl-64">
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Händlerverwaltung</h1>
          <p className="text-sm text-slate-500">{dealers.length} registrierte Händler</p>
        </div>

        <div className="p-8">
          {loading ? (
            <div className="animate-pulse text-slate-400 text-center py-12">Laden...</div>
          ) : (
            <div className="card overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50 text-left">
                    <th className="px-6 py-3 font-semibold text-slate-500">Unternehmen</th>
                    <th className="px-6 py-3 font-semibold text-slate-500">Standort</th>
                    <th className="px-6 py-3 font-semibold text-slate-500">Tier</th>
                    <th className="px-6 py-3 font-semibold text-slate-500">Boote</th>
                    <th className="px-6 py-3 font-semibold text-slate-500">Leads</th>
                    <th className="px-6 py-3 font-semibold text-slate-500">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {dealers.map((d) => (
                    <tr key={d.id} className="hover:bg-slate-50 transition">
                      <td className="px-6 py-4">
                        <p className="font-semibold text-slate-900">{d.companyName}</p>
                        <p className="text-xs text-slate-400">{d.user.email}</p>
                      </td>
                      <td className="px-6 py-4 text-slate-600">{d.city ?? "–"}, {d.country}</td>
                      <td className="px-6 py-4">
                        <span className={`badge ${TIER_BADGE[d.tier] ?? ""}`}>{d.tier}</span>
                      </td>
                      <td className="px-6 py-4 font-medium text-slate-700">{d._count.boats}</td>
                      <td className="px-6 py-4 font-medium text-slate-700">{d._count.leads}</td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span className={`badge ${d.isVerified ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"}`}>
                            {d.isVerified ? "Verifiziert" : "Ausstehend"}
                          </span>
                          {!d.isActive && <span className="badge bg-red-50 text-red-600">Gesperrt</span>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
