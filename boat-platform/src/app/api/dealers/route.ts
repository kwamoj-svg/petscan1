import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { prisma } from "@/lib/db";
import { authOptions } from "@/lib/auth";

export async function GET() {
  const session = await getServerSession(authOptions);
  if (session?.user?.role !== "ADMIN") {
    return NextResponse.json({ error: "Nicht autorisiert" }, { status: 403 });
  }

  const dealers = await prisma.dealer.findMany({
    include: {
      user: { select: { email: true, name: true, isActive: true } },
      subscription: { select: { plan: true, status: true } },
      _count: { select: { boats: true, leads: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json(dealers);
}
