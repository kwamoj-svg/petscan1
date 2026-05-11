import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { prisma } from "@/lib/db";
import { authOptions } from "@/lib/auth";
import { leadSchema } from "@/lib/validations";
import { routeLeadToDealer } from "@/lib/lead-routing";

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: "Nicht autorisiert" }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const status = searchParams.get("status");

  const where: Record<string, unknown> = {};

  if (session.user.role === "DEALER" && session.user.dealerId) {
    where.dealerId = session.user.dealerId;
  } else if (session.user.role !== "ADMIN") {
    return NextResponse.json({ error: "Kein Zugriff" }, { status: 403 });
  }

  if (status) where.status = status;

  const leads = await prisma.lead.findMany({
    where,
    include: {
      boat: { select: { name: true, brand: true, model: true, basePrice: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json(leads);
}

export async function POST(req: NextRequest) {
  const body = await req.json();
  const parsed = leadSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  let dealerId: string | null = null;

  if (parsed.data.boatId) {
    const boat = await prisma.boat.findUnique({
      where: { id: parsed.data.boatId, isActive: true },
      select: { dealerId: true },
    });
    if (!boat) {
      return NextResponse.json({ error: "Boot nicht gefunden" }, { status: 404 });
    }
    dealerId = boat.dealerId;
  } else if (parsed.data.configData) {
    dealerId = await routeLeadToDealer(parsed.data.configData as Record<string, unknown>);
  }

  if (!dealerId) {
    const fallback = await prisma.dealer.findFirst({ where: { isActive: true }, select: { id: true } });
    dealerId = fallback?.id ?? null;
  }

  if (!dealerId) {
    return NextResponse.json({ error: "Kein passender Händler gefunden" }, { status: 404 });
  }

  const { configData, ...restData } = parsed.data;
  const lead = await prisma.lead.create({
    data: {
      ...restData,
      configData: configData ? JSON.parse(JSON.stringify(configData)) : undefined,
      dealerId,
      source: parsed.data.source ?? "CONFIGURATOR",
    },
  });

  return NextResponse.json({ leadNumber: lead.leadNumber }, { status: 201 });
}
