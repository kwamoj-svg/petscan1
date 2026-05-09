"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import AdminSidebar from "@/components/admin/AdminSidebar";
import LeadStatusBadge from "@/components/ui/LeadStatusBadge";

interface Lead {
  id: string;
  leadNumber: string;
  customerName: string;
  customerEmail: string;
  totalPrice: number | null;
  status: string;
  source: string;
  createdAt: string;
  boat: { name: string; brand: string; model: string } | null;
}

export default function AdminLeadsPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [leads, setLeads] = useState<Lead[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (status === "unauthenticated") router.push("/admin/login");
    if (status === "authenticated" && session?.user?.role !== "ADMIN") router.push("/");
  }, [status, session, router]);

  useEffect(() => {
    if (status !== "authenticated") return;
    fetch("/api/leads").then((r) => r.json()).then((data) => {
      setLeads(Array.isArray(data) ? data : []);
      setLoading(false);
    });
  }, [status]);

  if (status !== "authenticated" || !session) return null;

  return (
    <div className="flex min-h-screen bg-slate-50">
      <AdminSidebar />
      <main className="flex-1 pl-64">
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Alle Leads</h1>
          <p className="text-sm text-slate-500">{leads.length} Leads plattformweit</p>
        </div>

        <div className="p-8">
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50 text-left">
                  <th className="px-6 py-3 font-semibold text-slate-500">Lead-Nr.</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Kunde</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Boot</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Preis</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Status</th>
                  <th className="px-6 py-3 font-semibold text-slate-500">Datum</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {leads.map((lead) => (
                  <tr key={lead.id} className="hover:bg-slate-50 transition">
                    <td className="px-6 py-4 font-mono text-xs text-slate-500">{lead.leadNumber.slice(0, 12)}...</td>
                    <td className="px-6 py-4">
                      <p className="font-semibold text-slate-900">{lead.customerName}</p>
                      <p className="text-xs text-slate-400">{lead.customerEmail}</p>
                    </td>
                    <td className="px-6 py-4 text-slate-600">
                      {lead.boat ? `${lead.boat.brand} ${lead.boat.model}` : "Konfigurator"}
                    </td>
                    <td className="px-6 py-4 font-medium text-slate-700">
                      {lead.totalPrice ? `${lead.totalPrice.toLocaleString("de-DE")} €` : "–"}
                    </td>
                    <td className="px-6 py-4"><LeadStatusBadge status={lead.status} /></td>
                    <td className="px-6 py-4 text-xs text-slate-400">
                      {new Date(lead.createdAt).toLocaleDateString("de-DE")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {leads.length === 0 && !loading && (
              <div className="py-12 text-center text-slate-500">Keine Leads vorhanden.</div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
