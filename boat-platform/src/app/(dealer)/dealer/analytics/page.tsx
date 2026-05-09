"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import DealerSidebar from "@/components/dealer/DealerSidebar";
import StatCard from "@/components/ui/StatCard";

interface Analytics {
  totalLeads: number;
  newLeads: number;
  wonLeads: number;
  conversionRate: string;
  leadsByStatus: { status: string; _count: number }[];
}

const STATUS_LABELS: Record<string, string> = {
  NEW: "Neu", CONTACTED: "Kontaktiert", OFFER_SENT: "Angebot gesendet",
  NEGOTIATING: "Verhandlung", WON: "Gewonnen", LOST: "Verloren",
};

const STATUS_COLORS: Record<string, string> = {
  NEW: "bg-blue-500", CONTACTED: "bg-amber-500", OFFER_SENT: "bg-purple-500",
  NEGOTIATING: "bg-indigo-500", WON: "bg-emerald-500", LOST: "bg-slate-400",
};

export default function DealerAnalyticsPage() {
  const { data: session, status: authStatus } = useSession();
  const router = useRouter();
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authStatus === "unauthenticated") router.push("/dealer/login");
  }, [authStatus, router]);

  useEffect(() => {
    if (authStatus !== "authenticated") return;
    fetch("/api/analytics")
      .then((r) => r.json())
      .then((data) => { setAnalytics(data); setLoading(false); });
  }, [authStatus]);

  if (authStatus === "loading" || loading || !session) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-pulse text-slate-400">Laden...</div>
      </div>
    );
  }

  const maxCount = Math.max(1, ...(analytics?.leadsByStatus?.map((s) => s._count) ?? [1]));

  return (
    <div className="flex min-h-screen bg-slate-50">
      <DealerSidebar companyName={session.user.companyName ?? session.user.name} />

      <main className="flex-1 pl-64">
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Statistiken</h1>
          <p className="text-sm text-slate-500">Übersicht Ihrer Vertriebsperformance</p>
        </div>

        <div className="p-8 space-y-8">
          {/* KPI Cards */}
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Gesamt-Leads" value={analytics?.totalLeads ?? 0} color="blue"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>}
            />
            <StatCard label="Neue Leads" value={analytics?.newLeads ?? 0} color="amber"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
            />
            <StatCard label="Gewonnen" value={analytics?.wonLeads ?? 0} color="green"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
            />
            <StatCard label="Conversion Rate" value={`${analytics?.conversionRate ?? 0}%`} color="purple"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg>}
            />
          </div>

          {/* Lead Pipeline */}
          <div className="card p-6">
            <h2 className="text-lg font-bold text-slate-900 mb-6">Lead-Pipeline</h2>
            <div className="space-y-4">
              {analytics?.leadsByStatus?.map((entry) => (
                <div key={entry.status} className="flex items-center gap-4">
                  <span className="w-36 text-sm font-medium text-slate-600">
                    {STATUS_LABELS[entry.status] ?? entry.status}
                  </span>
                  <div className="flex-1 h-8 rounded-lg bg-slate-100 overflow-hidden">
                    <div
                      className={`h-full rounded-lg ${STATUS_COLORS[entry.status] ?? "bg-slate-400"} transition-all duration-700`}
                      style={{ width: `${(entry._count / maxCount) * 100}%` }}
                    />
                  </div>
                  <span className="w-12 text-right text-sm font-bold text-slate-700">{entry._count}</span>
                </div>
              ))}
              {(!analytics?.leadsByStatus || analytics.leadsByStatus.length === 0) && (
                <p className="text-sm text-slate-500 text-center py-8">Noch keine Daten vorhanden.</p>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
