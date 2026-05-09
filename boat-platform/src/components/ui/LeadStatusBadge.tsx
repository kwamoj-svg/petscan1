const STATUS_CONFIG: Record<string, { label: string; className: string }> = {
  NEW: { label: "Neu", className: "bg-blue-50 text-blue-700 ring-1 ring-blue-600/20" },
  CONTACTED: { label: "Kontaktiert", className: "bg-amber-50 text-amber-700 ring-1 ring-amber-600/20" },
  OFFER_SENT: { label: "Angebot gesendet", className: "bg-purple-50 text-purple-700 ring-1 ring-purple-600/20" },
  NEGOTIATING: { label: "Verhandlung", className: "bg-indigo-50 text-indigo-700 ring-1 ring-indigo-600/20" },
  WON: { label: "Gewonnen", className: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-600/20" },
  LOST: { label: "Verloren", className: "bg-slate-100 text-slate-500 ring-1 ring-slate-300" },
};

export default function LeadStatusBadge({ status }: { status: string }) {
  const config = STATUS_CONFIG[status] ?? { label: status, className: "bg-slate-100 text-slate-600" };
  return (
    <span className={`badge ${config.className}`}>
      {config.label}
    </span>
  );
}
