import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { prisma } from "@/lib/db";
import { authOptions } from "@/lib/auth";

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user?.dealerId && session?.user?.role !== "ADMIN") {
    return NextResponse.json({ error: "Nicht autorisiert" }, { status: 403 });
  }

  const dealerFilter = session.user.role === "ADMIN"
    ? {}
    : { dealerId: session.user.dealerId! };

  const [totalLeads, newLeads, wonLeads, leadsByStatus, topBoats] = await Promise.all([
    prisma.lead.count({ where: dealerFilter }),
    prisma.lead.count({ where: { ...dealerFilter, status: "NEW" } }),
    prisma.lead.count({ where: { ...dealerFilter, status: "WON" } }),
    prisma.lead.groupBy({
      by: ["status"],
      where: dealerFilter,
      _count: true,
    }),
    prisma.lead.groupBy({
      by: ["boatId"],
      where: { ...dealerFilter, boatId: { not: null } },
      _count: true,
      orderBy: { _count: { boatId: "desc" } },
      take: 5,
    }),
  ]);

  const conversionRate = totalLeads > 0 ? ((wonLeads / totalLeads) * 100).toFixed(1) : "0";

  return NextResponse.json({
    totalLeads,
    newLeads,
    wonLeads,
    conversionRate,
    leadsByStatus,
    topBoats,
  });
}
