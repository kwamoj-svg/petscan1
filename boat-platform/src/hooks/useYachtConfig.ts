import { create } from "zustand";

export interface YachtConfig {
  hullColor: string;
  hullMaterial: "glossy" | "matte" | "carbon";
  deckMaterial: "teak" | "white" | "dark";
  accentColor: "gold" | "silver" | "rose-gold" | "black-chrome";
  features: {
    jacuzzi: boolean;
    helipad: boolean;
    sunbathing: boolean;
    pool: boolean;
  };
  lightingMood: "sunset" | "night" | "mediterranean" | "storm";
  presentationMode: boolean;
  configOpen: boolean;
}

interface YachtStore extends YachtConfig {
  setHullColor: (color: string) => void;
  setHullMaterial: (material: YachtConfig["hullMaterial"]) => void;
  setDeckMaterial: (material: YachtConfig["deckMaterial"]) => void;
  setAccentColor: (color: YachtConfig["accentColor"]) => void;
  toggleFeature: (feature: keyof YachtConfig["features"]) => void;
  setLightingMood: (mood: YachtConfig["lightingMood"]) => void;
  togglePresentationMode: () => void;
  toggleConfig: () => void;
}

export const useYachtConfig = create<YachtStore>((set) => ({
  hullColor: "#F8F9FA",
  hullMaterial: "glossy",
  deckMaterial: "teak",
  accentColor: "gold",
  features: {
    jacuzzi: false,
    helipad: false,
    sunbathing: true,
    pool: false,
  },
  lightingMood: "mediterranean",
  presentationMode: false,
  configOpen: true,

  setHullColor: (color) => set({ hullColor: color }),
  setHullMaterial: (material) => set({ hullMaterial: material }),
  setDeckMaterial: (material) => set({ deckMaterial: material }),
  setAccentColor: (color) => set({ accentColor: color }),
  toggleFeature: (feature) =>
    set((state) => ({
      features: { ...state.features, [feature]: !state.features[feature] },
    })),
  setLightingMood: (mood) => set({ lightingMood: mood }),
  togglePresentationMode: () =>
    set((state) => ({ presentationMode: !state.presentationMode, configOpen: false })),
  toggleConfig: () => set((state) => ({ configOpen: !state.configOpen })),
}));

// Lighting presets
export const LIGHTING_PRESETS = {
  sunset: {
    sunColor: "#ff8c42",
    sunIntensity: 2.0,
    ambientColor: "#ffd4a3",
    ambientIntensity: 0.4,
    fogColor: "#1a0f05",
    waterColor: "#0a3d62",
    bgColor: "#0d0805",
  },
  night: {
    sunColor: "#4a6fa5",
    sunIntensity: 0.5,
    ambientColor: "#1a2744",
    ambientIntensity: 0.3,
    fogColor: "#050a15",
    waterColor: "#030810",
    bgColor: "#020408",
  },
  mediterranean: {
    sunColor: "#fff5e6",
    sunIntensity: 2.5,
    ambientColor: "#cce0ff",
    ambientIntensity: 0.6,
    fogColor: "#0a1628",
    waterColor: "#0a3d62",
    bgColor: "#060d18",
  },
  storm: {
    sunColor: "#8899aa",
    sunIntensity: 0.8,
    ambientColor: "#445566",
    ambientIntensity: 0.3,
    fogColor: "#0a0d12",
    waterColor: "#0a1520",
    bgColor: "#080a0e",
  },
};

// Hull color presets
export const HULL_COLORS = [
  { key: "pearl", label: "Pearl White", hex: "#F8F9FA" },
  { key: "midnight", label: "Midnight Black", hex: "#1A1A2E" },
  { key: "navy", label: "Navy Blue", hex: "#1B2A4A" },
  { key: "champagne", label: "Champagne Gold", hex: "#C9B99A" },
  { key: "graphite", label: "Graphite", hex: "#4A4E69" },
  { key: "racing", label: "Racing Green", hex: "#004225" },
  { key: "bordeaux", label: "Bordeaux", hex: "#6B2737" },
];

// Accent color presets
export const ACCENT_COLORS = {
  gold: "#D4AF37",
  silver: "#C0C0C0",
  "rose-gold": "#B76E79",
  "black-chrome": "#2C2C2C",
};
