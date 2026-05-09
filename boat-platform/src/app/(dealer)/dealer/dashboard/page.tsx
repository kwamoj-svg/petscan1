"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import DealerSidebar from "@/components/dealer/DealerSidebar";
import StatCard from "@/components/ui/StatCard";
import LeadStatusBadge from "@/components/ui/LeadStatusBadge";

interface Lead {
  id: string;
  leadNumber: string;
  customerName: string;
  customerEmail: string;
  customerPhone: string | null;
  message: string | null;
  totalPrice: number | null;
  status: string;
  source: string;
  createdAt: string;
  boat: { name: string; brand: string; model: string; basePrice: number } | null;
}

interface Analytics {
  totalLeads: number;
  newLeads: number;
  wonLeads: number;
  conversionRate: string;
}

export default function DealerDashboardPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [leads, setLeads] = useState<Lead[]>([]);
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (status === "unauthenticated") router.push("/dealer/login");
  }, [status, router]);

  useEffect(() => {
    if (status !== "authenticated") return;
    Promise.all([
      fetch("/api/leads").then((r) => r.json()),
      fetch("/api/analytics").then((r) => r.json()),
    ]).then(([leadsData, analyticsData]) => {
      setLeads(Array.isArray(leadsData) ? leadsData : []);
      setAnalytics(analyticsData);
      setLoading(false);
    });
  }, [status]);

  if (status === "loading" || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-pulse text-slate-400">Laden...</div>
      </div>
    );
  }

  if (!session) return null;

  const recentLeads = leads.slice(0, 5);

  return (
    <div className="flex min-h-screen bg-slate-50">
      <DealerSidebar companyName={session.user.companyName ?? session.user.name} />

      <main className="flex-1 pl-64">
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Dashboard</h1>
          <p className="text-sm text-slate-500">Willkommen zurück, {session.user.name}</p>
        </div>

        <div className="p-8 space-y-8">
          {/* Stats */}
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard
              label="Gesamt-Leads"
              value={analytics?.totalLeads ?? 0}
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>}
              color="blue"
            />
            <StatCard
              label="Neue Leads"
              value={analytics?.newLeads ?? 0}
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
              color="amber"
            />
            <StatCard
              label="Gewonnen"
              value={analytics?.wonLeads ?? 0}
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
              color="green"
            />
            <StatCard
              label="Conversion Rate"
              value={`${analytics?.conversionRate ?? 0}%`}
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg>}
              color="purple"
            />
          </div>

          {/* Recent Leads */}
          <div className="card">
            <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4">
              <h2 className="text-lg font-bold text-slate-900">Neueste Leads</h2>
              <a href="/dealer/leads" className="text-sm font-medium text-sky-600 hover:text-sky-700">
                Alle anzeigen →
              </a>
            </div>
            {recentLeads.length === 0 ? (
              <div className="p-12 text-center text-slate-500">
                Noch keine Leads vorhanden.
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {recentLeads.map((lead) => (
                  <div key={lead.id} className="flex items-center justify-between px-6 py-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-sky-100 text-sm font-bold text-sky-700">
                          {lead.customerName.charAt(0).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <p className="font-semibold text-slate-900 truncate">{lead.customerName}</p>
                          <p className="text-sm text-slate-500 truncate">
                            {lead.boat ? `${lead.boat.brand} ${lead.boat.model}` : "Konfigurator-Anfrage"}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {lead.totalPrice && (
                        <span className="text-sm font-semibold text-slate-700">
                          {lead.totalPrice.toLocaleString("de-DE")} €
                        </span>
                      )}
                      <LeadStatusBadge status={lead.status} />
                      <span className="text-xs text-slate-400">
                        {new Date(lead.createdAt).toLocaleDateString("de-DE")}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
