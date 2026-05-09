import { prisma } from "./db";
import type { BoatCategory } from "@prisma/client";

interface ConfigData {
  category?: BoatCategory;
  budget?: number;
  region?: string;
}

export async function findMatchingDealers(config: ConfigData) {
  const where: Record<string, unknown> = {
    isActive: true,
    isVerified: true,
  };

  const dealers = await prisma.dealer.findMany({
    where,
    include: {
      specialties: true,
      subscription: true,
      _count: { select: { leads: true } },
    },
    orderBy: { createdAt: "asc" },
  });

  const scored = dealers.map((dealer) => {
    let score = 0;

    if (config.category) {
      const hasSpecialty = dealer.specialties.some((s) => s.category === config.category);
      if (hasSpecialty) score += 30;
    }

    if (dealer.tier === "ENTERPRISE") score += 20;
    else if (dealer.tier === "PREMIUM") score += 10;

    if (dealer.subscription?.status === "ACTIVE") score += 10;

    const leadCount = dealer._count.leads;
    if (leadCount < 10) score += 15;
    else if (leadCount < 50) score += 5;

    if (config.region && dealer.city?.toLowerCase().includes(config.region.toLowerCase())) {
      score += 25;
    }

    return { dealer, score };
  });

  return scored
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map((s) => s.dealer);
}

export async function routeLeadToDealer(config: ConfigData): Promise<string | null> {
  const dealers = await findMatchingDealers(config);
  return dealers[0]?.id ?? null;
}
