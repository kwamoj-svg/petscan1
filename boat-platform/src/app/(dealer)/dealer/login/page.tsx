"use client";

import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import Link from "next/link";

export default function DealerLoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const res = await signIn("credentials", { email, password, redirect: false });
    setLoading(false);

    if (res?.error) {
      setError("Ungültige Anmeldedaten");
    } else {
      router.push("/dealer/dashboard");
    }
  }

  return (
    <main className="flex min-h-screen">
      {/* Left: Form */}
      <div className="flex flex-1 items-center justify-center px-4 py-12">
        <div className="w-full max-w-sm">
          <Link href="/" className="flex items-center gap-2 mb-12">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-600">
              <svg className="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4" />
              </svg>
            </div>
            <span className="text-xl font-bold text-slate-900">BoatConnect</span>
          </Link>

          <h1 className="text-3xl font-extrabold text-slate-900">Händler-Login</h1>
          <p className="mt-2 text-slate-500">Melden Sie sich an, um Ihre Boote und Leads zu verwalten.</p>

          <form onSubmit={handleSubmit} className="mt-8 space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">E-Mail</label>
              <input required type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="input" placeholder="haendler@beispiel.de" />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Passwort</label>
              <input required type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="input" placeholder="••••••••" />
            </div>
            {error && (
              <div className="rounded-lg bg-red-50 border border-red-100 p-3 text-sm text-red-700">{error}</div>
            )}
            <button type="submit" disabled={loading} className="btn-primary w-full py-3.5">
              {loading ? "Anmelden..." : "Anmelden"}
            </button>
          </form>

          <div className="mt-8 rounded-xl bg-slate-50 p-4">
            <p className="text-xs font-semibold text-slate-500 mb-1">Demo-Zugangsdaten:</p>
            <p className="text-sm text-slate-600">demo@boothandel.de / demo1234</p>
            <p className="text-sm text-slate-600">admin@boatconnect.de / admin1234</p>
          </div>
        </div>
      </div>

      {/* Right: Visual */}
      <div className="hidden lg:block lg:flex-1 relative">
        <img
          src="https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=1200&h=1600&fit=crop"
          alt="Yacht"
          className="h-full w-full object-cover"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-white via-transparent to-transparent" />
      </div>
    </main>
  );
}
