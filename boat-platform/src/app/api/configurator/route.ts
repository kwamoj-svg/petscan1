import { NextRequest, NextResponse } from "next/server";
import { configSchema } from "@/lib/validations";
import { getRecommendations } from "@/lib/recommendations";
import { prisma } from "@/lib/db";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const parsed = configSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  const criteria = {
    category: parsed.data.category,
    minPrice: undefined as number | undefined,
    maxPrice: parsed.data.budget,
    minLength: parsed.data.minLength,
    maxLength: parsed.data.maxLength,
    brand: parsed.data.brand,
    cabins: parsed.data.cabins,
    useCase: parsed.data.useCase,
    engineType: parsed.data.engineType,
  };

  const recommendations = await getRecommendations(criteria);

  await prisma.configuration.create({
    data: {
      data: JSON.parse(JSON.stringify(parsed.data)),
      sessionId: req.headers.get("x-session-id") ?? undefined,
    },
  });

  return NextResponse.json({ recommendations });
}
