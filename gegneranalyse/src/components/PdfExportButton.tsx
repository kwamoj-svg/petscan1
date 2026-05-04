'use client';

import { AnalysisReport } from '@/types/analysis';
import { useCallback, useState } from 'react';

interface PdfExportButtonProps {
  report: AnalysisReport;
}

export default function PdfExportButton({ report }: PdfExportButtonProps) {
  const [exporting, setExporting] = useState(false);

  const handleExport = useCallback(async () => {
    setExporting(true);
    try {
      const html2pdfModule = await import('html2pdf.js');
      const html2pdf = html2pdfModule.default;

      const element = document.getElementById('report-content');
      if (!element) {
        console.error('Report-Element nicht gefunden');
        return;
      }

      const date = new Date().toISOString().split('T')[0];
      const filename = `Gegneranalyse_${report.team.replace(/\s+/g, '_')}_${date}.pdf`;

      const opt = {
        margin: [10, 10, 10, 10],
        filename,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: {
          scale: 2,
          backgroundColor: '#0a0f1a',
          useCORS: true,
        },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' as const },
      };

      await html2pdf().set(opt).from(element).save();
    } catch (err) {
      console.error('PDF-Export fehlgeschlagen:', err);
    } finally {
      setExporting(false);
    }
  }, [report.team]);

  return (
    <button
      onClick={handleExport}
      disabled={exporting}
      className="inline-flex items-center gap-2 px-5 py-2.5 bg-scout-card border border-scout-border rounded-lg text-gray-200 hover:bg-scout-border transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
    >
      <svg
        className="w-5 h-5"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        />
      </svg>
      {exporting ? 'Exportiere...' : 'Als PDF herunterladen'}
    </button>
  );
}
