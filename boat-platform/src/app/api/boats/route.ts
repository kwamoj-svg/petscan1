import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { prisma } from "@/lib/db";
import { authOptions } from "@/lib/auth";
import { boatSchema } from "@/lib/validations";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const category = searchParams.get("category");
  const brand = searchParams.get("brand");
  const minPrice = searchParams.get("minPrice");
  const maxPrice = searchParams.get("maxPrice");
  const featured = searchParams.get("featured");
  const limit = parseInt(searchParams.get("limit") ?? "20");
  const offset = parseInt(searchParams.get("offset") ?? "0");

  const where: Record<string, unknown> = { isActive: true };
  if (category) where.category = category;
  if (brand) where.brand = { contains: brand, mode: "insensitive" };
  if (featured === "true") where.isFeatured = true;
  if (minPrice || maxPrice) {
    where.basePrice = {};
    if (minPrice) (where.basePrice as Record<string, number>).gte = parseFloat(minPrice);
    if (maxPrice) (where.basePrice as Record<string, number>).lte = parseFloat(maxPrice);
  }

  const [boats, total] = await Promise.all([
    prisma.boat.findMany({
      where,
      include: {
        images: { where: { isPrimary: true }, take: 1 },
        dealer: { select: { companyName: true, city: true } },
        _count: { select: { leads: true } },
      },
      orderBy: [{ isFeatured: "desc" }, { createdAt: "desc" }],
      take: limit,
      skip: offset,
    }),
    prisma.boat.count({ where }),
  ]);

  return NextResponse.json({ boats, total, limit, offset });
}

export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.dealerId) {
    return NextResponse.json({ error: "Nicht autorisiert" }, { status: 401 });
  }

  const body = await req.json();
  const parsed = boatSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  const boat = await prisma.boat.create({
    data: { ...parsed.data, dealerId: session.user.dealerId },
  });

  return NextResponse.json(boat, { status: 201 });
}
