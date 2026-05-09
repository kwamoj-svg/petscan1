import { PrismaClient, BoatCategory, UseCase, LeadStatus, LeadSource } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const hash = (pw: string) => bcrypt.hashSync(pw, 12);

  // ─── ADMIN USER ─────────────────────────────────────
  await prisma.user.upsert({
    where: { email: "admin@boatconnect.de" },
    update: {},
    create: {
      email: "admin@boatconnect.de",
      passwordHash: hash("admin1234"),
      name: "BoatConnect Admin",
      role: "ADMIN",
    },
  });

  // ─── DEALER 1 ───────────────────────────────────────
  const dealerUser1 = await prisma.user.upsert({
    where: { email: "demo@boothandel.de" },
    update: {},
    create: {
      email: "demo@boothandel.de",
      passwordHash: hash("demo1234"),
      name: "Max Mustermann",
      role: "DEALER",
    },
  });

  const dealer1 = await prisma.dealer.upsert({
    where: { userId: dealerUser1.id },
    update: {},
    create: {
      userId: dealerUser1.id,
      companyName: "Maritime Bayern GmbH",
      description: "Ihr Premium-Bootshändler am Starnberger See. Über 30 Jahre Erfahrung.",
      city: "Starnberg",
      zipCode: "82319",
      country: "DE",
      tier: "PREMIUM",
      isVerified: true,
      specialties: {
        create: [
          { category: "YACHT" },
          { category: "SPORTBOAT" },
        ],
      },
      subscription: {
        create: { plan: "PREMIUM", status: "ACTIVE" },
      },
    },
  });

  // ─── DEALER 2 ───────────────────────────────────────
  const dealerUser2 = await prisma.user.upsert({
    where: { email: "info@nordsee-boote.de" },
    update: {},
    create: {
      email: "info@nordsee-boote.de",
      passwordHash: hash("demo1234"),
      name: "Anna Schmidt",
      role: "DEALER",
    },
  });

  const dealer2 = await prisma.dealer.upsert({
    where: { userId: dealerUser2.id },
    update: {},
    create: {
      userId: dealerUser2.id,
      companyName: "Nordsee Boote & Yachten",
      description: "Segelboote und Katamarane direkt an der Nordseeküste.",
      city: "Hamburg",
      zipCode: "20457",
      country: "DE",
      tier: "ENTERPRISE",
      isVerified: true,
      specialties: {
        create: [
          { category: "SAILBOAT" },
          { category: "CATAMARAN" },
        ],
      },
      subscription: {
        create: { plan: "ENTERPRISE", status: "ACTIVE" },
      },
    },
  });

  // ─── DEALER 3 ───────────────────────────────────────
  const dealerUser3 = await prisma.user.upsert({
    where: { email: "kontakt@bodensee-marine.de" },
    update: {},
    create: {
      email: "kontakt@bodensee-marine.de",
      passwordHash: hash("demo1234"),
      name: "Thomas Weber",
      role: "DEALER",
    },
  });

  const dealer3 = await prisma.dealer.upsert({
    where: { userId: dealerUser3.id },
    update: {},
    create: {
      userId: dealerUser3.id,
      companyName: "Bodensee Marine Center",
      description: "Jetskis, Sportboote und Wassersport-Equipment.",
      city: "Konstanz",
      zipCode: "78462",
      country: "DE",
      tier: "BASIC",
      isVerified: true,
      specialties: {
        create: [
          { category: "JETSKI" },
          { category: "SPORTBOAT" },
        ],
      },
      subscription: {
        create: { plan: "BASIC", status: "ACTIVE" },
      },
    },
  });

  // ─── BOATS ──────────────────────────────────────────
  const boatsData = [
    {
      dealerId: dealer1.id,
      name: "Prestige 520 Flybridge",
      brand: "Prestige",
      model: "520 Flybridge",
      year: 2025,
      basePrice: 895000,
      category: "YACHT" as BoatCategory,
      lengthM: 16.2,
      beamM: 4.6,
      weightKg: 18500,
      engineType: "Innenborder",
      engineBrand: "Volvo Penta",
      maxPowerHP: 800,
      fuelType: "DIESEL" as const,
      hullMaterial: "GFK",
      maxSpeed: 28,
      cabins: 3,
      berths: 6,
      heads: 2,
      hasKitchen: true,
      hasSoundSystem: true,
      hasSolarPanel: true,
      hasSmartSystem: true,
      useCase: ["LUXURY", "CRUISING"] as UseCase[],
      description: "Die Prestige 520 Flybridge bietet luxuriöses Cruising mit elegantem Design, drei geräumigen Kabinen und einer voll ausgestatteten Küche.",
      location: "Starnberg, Deutschland",
      isFeatured: true,
    },
    {
      dealerId: dealer1.id,
      name: "Bayliner VR6",
      brand: "Bayliner",
      model: "VR6",
      year: 2025,
      basePrice: 65000,
      category: "SPORTBOAT" as BoatCategory,
      lengthM: 6.4,
      beamM: 2.5,
      engineType: "Außenborder",
      engineBrand: "Mercury",
      maxPowerHP: 250,
      fuelType: "PETROL" as const,
      hullMaterial: "GFK",
      maxSpeed: 75,
      cabins: 0,
      hasSoundSystem: true,
      useCase: ["LEISURE", "WATERSPORT"] as UseCase[],
      description: "Der Bayliner VR6 ist das perfekte Sportboot für Familien. Kompakt, wendig und mit reichlich Platz.",
      location: "Starnberg, Deutschland",
      isFeatured: true,
    },
    {
      dealerId: dealer2.id,
      name: "Beneteau Oceanis 46.1",
      brand: "Beneteau",
      model: "Oceanis 46.1",
      year: 2024,
      basePrice: 320000,
      category: "SAILBOAT" as BoatCategory,
      lengthM: 14.6,
      beamM: 4.5,
      draftM: 2.3,
      weightKg: 11800,
      engineType: "Innenborder",
      engineBrand: "Yanmar",
      maxPowerHP: 57,
      fuelType: "DIESEL" as const,
      hullMaterial: "GFK",
      cabins: 4,
      berths: 8,
      heads: 2,
      hasKitchen: true,
      hasSoundSystem: true,
      useCase: ["CRUISING", "CHARTER"] as UseCase[],
      description: "Die Oceanis 46.1 ist eine vielseitige Segelyacht für anspruchsvolle Langstrecken-Segler.",
      location: "Hamburg, Deutschland",
      isFeatured: true,
    },
    {
      dealerId: dealer2.id,
      name: "Lagoon 42",
      brand: "Lagoon",
      model: "42",
      year: 2025,
      basePrice: 485000,
      category: "CATAMARAN" as BoatCategory,
      lengthM: 12.8,
      beamM: 7.7,
      draftM: 1.3,
      engineType: "Innenborder",
      engineBrand: "Yanmar",
      maxPowerHP: 114,
      fuelType: "DIESEL" as const,
      cabins: 4,
      berths: 8,
      heads: 4,
      hasKitchen: true,
      hasSoundSystem: true,
      hasSolarPanel: true,
      hasSmartSystem: true,
      useCase: ["LUXURY", "CHARTER", "CRUISING"] as UseCase[],
      description: "Der Lagoon 42 ist der Inbegriff von Komfort auf dem Wasser — ideal für Charter und Langstrecken.",
      location: "Hamburg, Deutschland",
    },
    {
      dealerId: dealer3.id,
      name: "Yamaha FX Cruiser SVHO",
      brand: "Yamaha",
      model: "FX Cruiser SVHO",
      year: 2025,
      basePrice: 22500,
      category: "JETSKI" as BoatCategory,
      lengthM: 3.6,
      beamM: 1.3,
      weightKg: 385,
      engineType: "Jet-Antrieb",
      engineBrand: "Yamaha",
      maxPowerHP: 260,
      fuelType: "PETROL" as const,
      maxSpeed: 110,
      cabins: 0,
      hasSoundSystem: true,
      useCase: ["WATERSPORT", "LEISURE"] as UseCase[],
      description: "Der FX Cruiser SVHO bietet ultimative Power und Komfort für Jetski-Enthusiasten.",
      location: "Konstanz, Deutschland",
      isFeatured: true,
    },
    {
      dealerId: dealer3.id,
      name: "Sea-Doo GTX Limited 300",
      brand: "Sea-Doo",
      model: "GTX Limited 300",
      year: 2025,
      basePrice: 24900,
      category: "JETSKI" as BoatCategory,
      lengthM: 3.5,
      beamM: 1.3,
      weightKg: 399,
      engineType: "Jet-Antrieb",
      engineBrand: "Rotax",
      maxPowerHP: 300,
      fuelType: "PETROL" as const,
      maxSpeed: 115,
      cabins: 0,
      hasSoundSystem: true,
      hasSmartSystem: true,
      useCase: ["WATERSPORT", "LEISURE"] as UseCase[],
      description: "Premium-Jetski mit Bluetooth-Audio, GPS und dem stärksten Rotax-Motor seiner Klasse.",
      location: "Konstanz, Deutschland",
    },
    {
      dealerId: dealer1.id,
      name: "Bavaria Vida 33",
      brand: "Bavaria",
      model: "Vida 33",
      year: 2024,
      basePrice: 195000,
      category: "SPORTBOAT" as BoatCategory,
      lengthM: 10.3,
      beamM: 3.4,
      engineType: "Innenborder",
      engineBrand: "Mercury",
      maxPowerHP: 350,
      fuelType: "DIESEL" as const,
      cabins: 1,
      berths: 2,
      heads: 1,
      hasKitchen: true,
      hasSoundSystem: true,
      useCase: ["LEISURE", "CRUISING"] as UseCase[],
      description: "Elegantes Daycruiser-Design trifft auf Übernachtungskomfort — made in Germany.",
      location: "Starnberg, Deutschland",
    },
    {
      dealerId: dealer2.id,
      name: "Hanse 460",
      brand: "Hanse",
      model: "460",
      year: 2025,
      basePrice: 395000,
      category: "SAILBOAT" as BoatCategory,
      lengthM: 14.1,
      beamM: 4.5,
      draftM: 2.2,
      weightKg: 12000,
      engineType: "Innenborder",
      engineBrand: "Yanmar",
      maxPowerHP: 57,
      fuelType: "DIESEL" as const,
      cabins: 3,
      berths: 6,
      heads: 2,
      hasKitchen: true,
      hasSoundSystem: true,
      hasSolarPanel: true,
      useCase: ["CRUISING", "RACING"] as UseCase[],
      description: "Die Hanse 460 vereint sportliches Segeln mit höchstem Komfort — ideal für Blauwasser-Segler.",
      location: "Hamburg, Deutschland",
    },
  ];

  for (const boatData of boatsData) {
    await prisma.boat.create({ data: boatData });
  }

  // ─── SAMPLE LEADS ──────────────────────────────────
  const boats = await prisma.boat.findMany({ select: { id: true, dealerId: true } });

  const leadsData = [
    { customerName: "Julia Becker", customerEmail: "julia.becker@gmail.com", customerPhone: "+49 171 2345678", message: "Ich interessiere mich für eine Probefahrt.", status: "NEW" as LeadStatus, source: "BOAT_LISTING" as LeadSource },
    { customerName: "Stefan Müller", customerEmail: "s.mueller@web.de", customerPhone: "+49 160 9876543", message: "Können Sie mir ein Angebot für Finanzierung machen?", status: "CONTACTED" as LeadStatus, source: "CONFIGURATOR" as LeadSource },
    { customerName: "Maria Schneider", customerEmail: "maria.s@outlook.de", message: "Suche eine Yacht für 6 Personen, Budget ca. 800k.", status: "OFFER_SENT" as LeadStatus, source: "CONFIGURATOR" as LeadSource },
    { customerName: "Klaus Wagner", customerEmail: "k.wagner@t-online.de", customerPhone: "+49 172 1111222", message: "Wann kann ich das Boot besichtigen?", status: "NEGOTIATING" as LeadStatus, source: "BOAT_LISTING" as LeadSource },
    { customerName: "Lisa Hoffmann", customerEmail: "lisa.hoff@gmail.com", message: "Tolles Boot, wir haben gekauft!", status: "WON" as LeadStatus, source: "BOAT_LISTING" as LeadSource },
    { customerName: "Peter Braun", customerEmail: "p.braun@gmx.de", message: "Doch nicht interessiert.", status: "LOST" as LeadStatus, source: "CONFIGURATOR" as LeadSource },
    { customerName: "Anke Fischer", customerEmail: "anke.f@yahoo.de", customerPhone: "+49 151 3334455", message: "Suche Jetski für den Bodensee.", status: "NEW" as LeadStatus, source: "CONFIGURATOR" as LeadSource },
    { customerName: "Martin Koch", customerEmail: "m.koch@firma.de", message: "Charter-Flotte Anfrage: 3 Katamarane.", status: "NEW" as LeadStatus, source: "DIRECT_CONTACT" as LeadSource, budget: 1500000 },
  ];

  for (let i = 0; i < leadsData.length; i++) {
    const boat = boats[i % boats.length];
    await prisma.lead.create({
      data: {
        ...leadsData[i],
        boatId: boat.id,
        dealerId: boat.dealerId,
        totalPrice: boatsData[i % boatsData.length].basePrice,
      },
    });
  }

  console.log("Seed complete: 1 admin + 3 dealers + 8 boats + 8 leads");
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
