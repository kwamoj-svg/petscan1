import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Gegneranalyse - Professionelles Scouting Tool',
  description:
    'Professionelles Fußball-Scouting und Gegneranalyse mit KI-gestützter Video- und Datenauswertung.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="de">
      <body className={`${inter.className} bg-scout-dark text-gray-100 min-h-screen`}>
        {children}
      </body>
    </html>
  );
}
