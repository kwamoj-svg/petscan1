"use client";

import Link from "next/link";
import { useState } from "react";

export default function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <nav className="fixed top-0 z-50 w-full border-b border-white/10 bg-white/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <Link href="/" className="flex items-center gap-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-600">
            <svg className="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4" />
            </svg>
          </div>
          <span className="text-xl font-bold text-slate-900">
            Boat<span className="text-sky-600">Connect</span>
          </span>
        </Link>

        <div className="hidden items-center gap-1 md:flex">
          <Link href="/boats" className="btn-ghost">Boote entdecken</Link>
          <Link href="/configurator" className="btn-ghost">Konfigurator</Link>
          <div className="mx-2 h-5 w-px bg-slate-200" />
          <Link href="/dealer/login" className="btn-ghost">Händler-Login</Link>
          <Link href="/configurator" className="btn-primary ml-2">
            Boot konfigurieren
          </Link>
        </div>

        <button onClick={() => setOpen(!open)} className="md:hidden p-2">
          <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            {open ? (
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            ) : (
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            )}
          </svg>
        </button>
      </div>

      {open && (
        <div className="border-t border-slate-100 bg-white px-4 py-4 md:hidden animate-fade-in">
          <div className="flex flex-col gap-2">
            <Link href="/boats" onClick={() => setOpen(false)} className="rounded-lg px-4 py-3 text-sm font-medium hover:bg-slate-50">Boote entdecken</Link>
            <Link href="/configurator" onClick={() => setOpen(false)} className="rounded-lg px-4 py-3 text-sm font-medium hover:bg-slate-50">Konfigurator</Link>
            <Link href="/dealer/login" onClick={() => setOpen(false)} className="rounded-lg px-4 py-3 text-sm font-medium hover:bg-slate-50">Händler-Login</Link>
            <Link href="/configurator" onClick={() => setOpen(false)} className="btn-primary mt-2">Boot konfigurieren</Link>
          </div>
        </div>
      )}
    </nav>
  );
}
