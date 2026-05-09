import Link from "next/link";

interface BoatCardProps {
  id: string;
  name: string;
  brand: string;
  model: string;
  year: number;
  basePrice: number;
  category: string;
  lengthM: number;
  cabins: number;
  imageUrl?: string;
  dealerName?: string;
  dealerCity?: string;
  isFeatured?: boolean;
}

const CATEGORY_LABELS: Record<string, string> = {
  YACHT: "Yacht",
  SPORTBOAT: "Sportboot",
  SAILBOAT: "Segelboot",
  CATAMARAN: "Katamaran",
  JETSKI: "Jetski",
  PONTOON: "Pontonboot",
  FISHING: "Angelboot",
  HOUSEBOAT: "Hausboot",
};

const PLACEHOLDER_IMAGES: Record<string, string> = {
  YACHT: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=600&h=400&fit=crop",
  SPORTBOAT: "https://images.unsplash.com/photo-1605281317010-fe5ffe798166?w=600&h=400&fit=crop",
  SAILBOAT: "https://images.unsplash.com/photo-1540946485063-a40da27545f8?w=600&h=400&fit=crop",
  CATAMARAN: "https://images.unsplash.com/photo-1559494007-9f5847c49d94?w=600&h=400&fit=crop",
  JETSKI: "https://images.unsplash.com/photo-1626447857058-2ba6a8868cb5?w=600&h=400&fit=crop",
  DEFAULT: "https://images.unsplash.com/photo-1544551763-46a013bb70d5?w=600&h=400&fit=crop",
};

export default function BoatCard({
  id, name, brand, model, year, basePrice, category, lengthM, cabins,
  imageUrl, dealerName, dealerCity, isFeatured,
}: BoatCardProps) {
  const img = imageUrl || PLACEHOLDER_IMAGES[category] || PLACEHOLDER_IMAGES.DEFAULT;

  return (
    <Link href={`/boats/${id}`} className="card group overflow-hidden">
      <div className="relative aspect-[4/3] overflow-hidden bg-slate-100">
        <img
          src={img}
          alt={name}
          className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-105"
        />
        {isFeatured && (
          <div className="absolute left-3 top-3 badge bg-amber-400 text-amber-900">
            Featured
          </div>
        )}
        <div className="absolute right-3 top-3 badge bg-white/90 text-slate-700 backdrop-blur-sm">
          {CATEGORY_LABELS[category] ?? category}
        </div>
      </div>

      <div className="p-5">
        <div className="mb-1 flex items-start justify-between gap-2">
          <h3 className="font-bold text-slate-900 line-clamp-1">{name}</h3>
          <span className="shrink-0 text-lg font-bold text-sky-600">
            {basePrice.toLocaleString("de-DE")} €
          </span>
        </div>

        <p className="text-sm text-slate-500">{brand} {model} &middot; {year}</p>

        <div className="mt-3 flex items-center gap-3 text-xs text-slate-400">
          <span className="flex items-center gap-1">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
            </svg>
            {lengthM} m
          </span>
          {cabins > 0 && (
            <span className="flex items-center gap-1">
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
              </svg>
              {cabins} Kabinen
            </span>
          )}
          {dealerName && (
            <span className="ml-auto text-slate-400">
              {dealerName}{dealerCity ? `, ${dealerCity}` : ""}
            </span>
          )}
        </div>
      </div>
    </Link>
  );
}
