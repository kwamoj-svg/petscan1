import { z } from "zod";

export const leadSchema = z.object({
  boatId: z.string().optional(),
  customerName: z.string().min(2).max(100),
  customerEmail: z.string().email(),
  customerPhone: z.string().max(30).optional(),
  message: z.string().max(5000).optional(),
  configData: z.record(z.unknown()).optional(),
  totalPrice: z.number().positive().optional(),
  budget: z.number().positive().optional(),
  source: z.enum(["CONFIGURATOR", "BOAT_LISTING", "DIRECT_CONTACT", "REFERRAL"]).optional(),
});

export const boatSchema = z.object({
  name: z.string().min(1).max(200),
  brand: z.string().min(1).max(100),
  model: z.string().min(1).max(100),
  year: z.number().int().min(1900).max(2100),
  condition: z.enum(["NEW", "USED", "REFURBISHED"]).optional(),
  basePrice: z.number().positive(),
  category: z.enum(["YACHT", "SPORTBOAT", "SAILBOAT", "CATAMARAN", "JETSKI", "PONTOON", "FISHING", "HOUSEBOAT"]),
  lengthM: z.number().positive(),
  beamM: z.number().positive().optional(),
  draftM: z.number().positive().optional(),
  weightKg: z.number().positive().optional(),
  engineType: z.string().max(100).optional(),
  engineBrand: z.string().max(100).optional(),
  maxPowerHP: z.number().int().positive().optional(),
  fuelType: z.enum(["DIESEL", "PETROL", "ELECTRIC", "HYBRID", "NONE"]).optional(),
  hullMaterial: z.string().max(100).optional(),
  maxSpeed: z.number().positive().optional(),
  cabins: z.number().int().min(0).optional(),
  berths: z.number().int().min(0).optional(),
  heads: z.number().int().min(0).optional(),
  hasKitchen: z.boolean().optional(),
  hasSoundSystem: z.boolean().optional(),
  hasSolarPanel: z.boolean().optional(),
  hasSmartSystem: z.boolean().optional(),
  useCase: z.array(z.enum(["LEISURE", "CHARTER", "LUXURY", "FISHING", "WATERSPORT", "RACING", "CRUISING"])).optional(),
  description: z.string().max(10000).optional(),
  location: z.string().max(200).optional(),
});

export const configSchema = z.object({
  category: z.enum(["YACHT", "SPORTBOAT", "SAILBOAT", "CATAMARAN", "JETSKI", "PONTOON", "FISHING", "HOUSEBOAT"]),
  budget: z.number().positive().optional(),
  minLength: z.number().positive().optional(),
  maxLength: z.number().positive().optional(),
  engineType: z.string().optional(),
  brand: z.string().optional(),
  cabins: z.number().int().min(0).optional(),
  useCase: z.enum(["LEISURE", "CHARTER", "LUXURY", "FISHING", "WATERSPORT", "RACING", "CRUISING"]).optional(),
  features: z.object({
    kitchen: z.boolean().optional(),
    soundSystem: z.boolean().optional(),
    solarPanel: z.boolean().optional(),
    smartSystem: z.boolean().optional(),
  }).optional(),
});

export type LeadInput = z.infer<typeof leadSchema>;
export type BoatInput = z.infer<typeof boatSchema>;
export type ConfigInput = z.infer<typeof configSchema>;
