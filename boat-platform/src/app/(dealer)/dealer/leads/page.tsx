"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import DealerSidebar from "@/components/dealer/DealerSidebar";
import LeadStatusBadge from "@/components/ui/LeadStatusBadge";

interface Lead {
  id: string;
  leadNumber: string;
  customerName: string;
  customerEmail: string;
  customerPhone: string | null;
  message: string | null;
  configData: Record<string, unknown> | null;
  totalPrice: number | null;
  budget: number | null;
  status: string;
  source: string;
  createdAt: string;
  boat: { name: string; brand: string; model: string; basePrice: number } | null;
}

const STATUS_FILTERS = [
  { key: "", label: "Alle" },
  { key: "NEW", label: "Neu" },
  { key: "CONTACTED", label: "Kontaktiert" },
  { key: "OFFER_SENT", label: "Angebot gesendet" },
  { key: "NEGOTIATING", label: "Verhandlung" },
  { key: "WON", label: "Gewonnen" },
  { key: "LOST", label: "Verloren" },
];

export default function DealerLeadsPage() {
  const { data: session, status: authStatus } = useSession();
  const router = useRouter();
  const [leads, setLeads] = useState<Lead[]>([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    if (authStatus === "unauthenticated") router.push("/dealer/login");
  }, [authStatus, router]);

  useEffect(() => {
    if (authStatus !== "authenticated") return;
    const params = filter ? `?status=${filter}` : "";
    fetch(`/api/leads${params}`)
      .then((r) => r.json())
      .then((data) => {
        setLeads(Array.isArray(data) ? data : []);
        setLoading(false);
      });
  }, [authStatus, filter]);

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
        <div className="border-b border-slate-200 bg-white px-8 py-6">
          <h1 className="text-2xl font-extrabold text-slate-900">Leads</h1>
          <p className="text-sm text-slate-500">{leads.length} Anfragen insgesamt</p>
        </div>

        <div className="p-8">
          {/* Filter */}
          <div className="mb-6 flex flex-wrap gap-2">
            {STATUS_FILTERS.map((sf) => (
              <button
                key={sf.key}
                onClick={() => { setFilter(sf.key); setLoading(true); }}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  filter === sf.key
                    ? "bg-sky-600 text-white"
                    : "bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50"
                }`}
              >
                {sf.label}
              </button>
            ))}
          </div>

          {/* Lead List */}
          <div className="space-y-3">
            {leads.length === 0 ? (
              <div className="card p-12 text-center text-slate-500">
                Keine Leads mit diesem Filter gefunden.
              </div>
            ) : (
              leads.map((lead) => (
                <div key={lead.id} className="card overflow-hidden">
                  <button
                    onClick={() => setExpandedId(expandedId === lead.id ? null : lead.id)}
                    className="flex w-full items-center justify-between px-6 py-4 text-left"
                  >
                    <div className="flex items-center gap-4">
                      <div className="flex h-11 w-11 items-center justify-center rounded-full bg-sky-100 text-sm font-bold text-sky-700">
                        {lead.customerName.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="font-semibold text-slate-900">{lead.customerName}</p>
                        <p className="text-sm text-slate-500">
                          {lead.customerEmail}
                          {lead.customerPhone && ` · ${lead.customerPhone}`}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {lead.totalPrice && (
                        <span className="text-sm font-bold text-slate-700">
                          {lead.totalPrice.toLocaleString("de-DE")} €
                        </span>
                      )}
                      <LeadStatusBadge status={lead.status} />
                      <span className="text-xs text-slate-400">
                        {new Date(lead.createdAt).toLocaleDateString("de-DE")}
                      </span>
                      <svg
                        className={`h-5 w-5 text-slate-400 transition-transform ${expandedId === lead.id ? "rotate-180" : ""}`}
                        fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                      </svg>
                    </div>
                  </button>

                  {expandedId === lead.id && (
                    <div className="border-t border-slate-100 bg-slate-50 px-6 py-4 animate-fade-in">
                      <div className="grid gap-4 sm:grid-cols-2">
                        <div>
                          <p className="text-xs font-medium uppercase text-slate-400">Boot</p>
                          <p className="mt-1 text-sm font-semibold text-slate-700">
                            {lead.boat ? `${lead.boat.brand} ${lead.boat.model} – ${lead.boat.name}` : "Konfigurator-Anfrage"}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs font-medium uppercase text-slate-400">Quelle</p>
                          <p className="mt-1 text-sm text-slate-700">
                            {lead.source === "CONFIGURATOR" ? "Konfigurator" : lead.source === "BOAT_LISTING" ? "Bootslisting" : lead.source}
                          </p>
                        </div>
                        {lead.budget && (
                          <div>
                            <p className="text-xs font-medium uppercase text-slate-400">Budget</p>
                            <p className="mt-1 text-sm text-slate-700">{lead.budget.toLocaleString("de-DE")} €</p>
                          </div>
                        )}
                        <div>
                          <p className="text-xs font-medium uppercase text-slate-400">Lead-Nr.</p>
                          <p className="mt-1 text-sm font-mono text-slate-500">{lead.leadNumber}</p>
                        </div>
                      </div>
                      {lead.message && (
                        <div className="mt-4">
                          <p className="text-xs font-medium uppercase text-slate-400">Nachricht</p>
                          <p className="mt-1 text-sm italic text-slate-600">&bdquo;{lead.message}&ldquo;</p>
                        </div>
                      )}
                      <div className="mt-4 flex gap-2">
                        <a href={`mailto:${lead.customerEmail}`} className="btn-primary text-xs py-2 px-4">
                          E-Mail senden
                        </a>
                        {lead.customerPhone && (
                          <a href={`tel:${lead.customerPhone}`} className="btn-secondary text-xs py-2 px-4">
                            Anrufen
                          </a>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
