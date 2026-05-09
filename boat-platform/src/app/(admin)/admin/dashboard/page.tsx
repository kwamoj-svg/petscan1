"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import AdminSidebar from "@/components/admin/AdminSidebar";
import StatCard from "@/components/ui/StatCard";

interface Stats {
  totalLeads: number;
  newLeads: number;
  wonLeads: number;
  conversionRate: string;
}

export default function AdminDashboardPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [stats, setStats] = useState<Stats | null>(null);
  const [dealerCount, setDealerCount] = useState(0);
  const [boatCount, setBoatCount] = useState(0);

  useEffect(() => {
    if (status === "unauthenticated") router.push("/admin/login");
    if (status === "authenticated" && session?.user?.role !== "ADMIN") router.push("/");
  }, [status, session, router]);

  useEffect(() => {
    if (status !== "authenticated") return;
    Promise.all([
      fetch("/api/analytics").then((r) => r.json()),
      fetch("/api/dealers").then((r) => r.json()),
      fetch("/api/boats?limit=1").then((r) => r.json()),
    ]).then(([analyticsData, dealersData, boatsData]) => {
      setStats(analyticsData);
      setDealerCount(Array.isArray(dealersData) ? dealersData.length : 0);
      setBoatCount(boatsData.total ?? 0);
    });
  }, [status]);

  if (status !== "authenticated" || !session) return null;

  return (
    <div className="flex min-h-screen bg-slate-50">
      <AdminSidebar />
      <main className="flex-1 pl-64">
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Admin-Übersicht</h1>
          <p className="text-sm text-slate-500">Plattform-weite Statistiken</p>
        </div>

        <div className="p-8 space-y-8">
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Händler" value={dealerCount} color="blue"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" /></svg>}
            />
            <StatCard label="Gelistete Boote" value={boatCount} color="green"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4" /></svg>}
            />
            <StatCard label="Gesamt-Leads" value={stats?.totalLeads ?? 0} color="amber"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>}
            />
            <StatCard label="Conversion" value={`${stats?.conversionRate ?? 0}%`} color="purple"
              icon={<svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg>}
            />
          </div>
        </div>
      </main>
    </div>
  );
}
