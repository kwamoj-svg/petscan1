"use client";

import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useState } from "react";

export default function AdminLoginPage() {
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
    if (res?.error) setError("Ungültige Anmeldedaten");
    else router.push("/admin/dashboard");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-900 px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center gap-2 mb-8">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500">
            <svg className="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
          </div>
          <span className="text-xl font-bold text-white">Admin Panel</span>
        </div>

        <div className="rounded-2xl bg-slate-800 p-8">
          <h1 className="text-2xl font-extrabold text-white">Admin-Login</h1>
          <form onSubmit={handleSubmit} className="mt-6 space-y-4">
            <input required type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-white placeholder-slate-500 outline-none focus:border-red-500" placeholder="admin@boatconnect.de" />
            <input required type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-white placeholder-slate-500 outline-none focus:border-red-500" placeholder="••••••••" />
            {error && <p className="text-sm text-red-400">{error}</p>}
            <button type="submit" disabled={loading} className="w-full rounded-lg bg-red-500 py-3 text-sm font-semibold text-white hover:bg-red-600 transition disabled:opacity-50">
              {loading ? "Anmelden..." : "Anmelden"}
            </button>
          </form>
          <p className="mt-4 text-xs text-slate-500 text-center">admin@boatconnect.de / admin1234</p>
        </div>
      </div>
    </main>
  );
}
