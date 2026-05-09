import { prisma } from "./db";
import type { BoatCategory } from "@prisma/client";

interface SearchCriteria {
  category?: BoatCategory;
  minPrice?: number;
  maxPrice?: number;
  minLength?: number;
  maxLength?: number;
  brand?: string;
  cabins?: number;
  useCase?: string;
  engineType?: string;
}

export async function getRecommendations(criteria: SearchCriteria, limit = 6) {
  const where: Record<string, unknown> = { isActive: true };

  if (criteria.category) where.category = criteria.category;
  if (criteria.brand) where.brand = { contains: criteria.brand, mode: "insensitive" };
  if (criteria.cabins) where.cabins = { gte: criteria.cabins };
  if (criteria.engineType) where.engineType = { contains: criteria.engineType, mode: "insensitive" };

  if (criteria.minPrice || criteria.maxPrice) {
    where.basePrice = {};
    if (criteria.minPrice) (where.basePrice as Record<string, number>).gte = criteria.minPrice;
    if (criteria.maxPrice) (where.basePrice as Record<string, number>).lte = criteria.maxPrice;
  }

  if (criteria.minLength || criteria.maxLength) {
    where.lengthM = {};
    if (criteria.minLength) (where.lengthM as Record<string, number>).gte = criteria.minLength;
    if (criteria.maxLength) (where.lengthM as Record<string, number>).lte = criteria.maxLength;
  }

  if (criteria.useCase) {
    where.useCase = { has: criteria.useCase };
  }

  const boats = await prisma.boat.findMany({
    where,
    include: {
      images: { where: { isPrimary: true }, take: 1 },
      dealer: { select: { companyName: true, city: true } },
    },
    orderBy: [{ isFeatured: "desc" }, { viewCount: "desc" }],
    take: limit,
  });

  return boats;
}

export async function getSimilarBoats(boatId: string, limit = 4) {
  const boat = await prisma.boat.findUnique({ where: { id: boatId } });
  if (!boat) return [];

  return prisma.boat.findMany({
    where: {
      id: { not: boatId },
      isActive: true,
      OR: [
        { category: boat.category },
        { brand: boat.brand },
        {
          basePrice: {
            gte: boat.basePrice * 0.7,
            lte: boat.basePrice * 1.3,
          },
        },
      ],
    },
    include: {
      images: { where: { isPrimary: true }, take: 1 },
      dealer: { select: { companyName: true } },
    },
    orderBy: { viewCount: "desc" },
    take: limit,
  });
}
