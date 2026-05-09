import Link from "next/link";

export default function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-slate-900 text-slate-400">
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-600">
                <svg className="h-4 w-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 17h1l1-2h14l1 2h1M5 15l2-8h10l2 8M12 3v4" />
                </svg>
              </div>
              <span className="text-lg font-bold text-white">BoatConnect</span>
            </div>
            <p className="text-sm leading-relaxed">
              Die führende Plattform für Bootskonfiguration und Händlervernetzung in Europa.
            </p>
          </div>

          <div>
            <h4 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-300">Plattform</h4>
            <ul className="space-y-2 text-sm">
              <li><Link href="/boats" className="hover:text-white transition">Boote entdecken</Link></li>
              <li><Link href="/configurator" className="hover:text-white transition">Konfigurator</Link></li>
              <li><Link href="/dealer/login" className="hover:text-white transition">Für Händler</Link></li>
            </ul>
          </div>

          <div>
            <h4 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-300">Bootstypen</h4>
            <ul className="space-y-2 text-sm">
              <li><Link href="/boats?category=YACHT" className="hover:text-white transition">Yachten</Link></li>
              <li><Link href="/boats?category=SPORTBOAT" className="hover:text-white transition">Sportboote</Link></li>
              <li><Link href="/boats?category=SAILBOAT" className="hover:text-white transition">Segelboote</Link></li>
              <li><Link href="/boats?category=CATAMARAN" className="hover:text-white transition">Katamarane</Link></li>
            </ul>
          </div>

          <div>
            <h4 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-300">Rechtliches</h4>
            <ul className="space-y-2 text-sm">
              <li><Link href="#" className="hover:text-white transition">Impressum</Link></li>
              <li><Link href="#" className="hover:text-white transition">Datenschutz</Link></li>
              <li><Link href="#" className="hover:text-white transition">AGB</Link></li>
            </ul>
          </div>
        </div>

        <div className="mt-12 border-t border-slate-800 pt-8 text-center text-sm">
          <p>&copy; {new Date().getFullYear()} BoatConnect. Alle Rechte vorbehalten.</p>
        </div>
      </div>
    </footer>
  );
}
