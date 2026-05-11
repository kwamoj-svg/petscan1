"use client";

import { useState } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";

// ═══════════════════════════════════════════════════════════════
//  AI YACHT MATCHING EXPERIENCE
//  Fullscreen · Cinematic · Immersive · Luxury
// ═══════════════════════════════════════════════════════════════

interface Config {
  mode: string | null;
  lifestyle: string | null;
  regions: string[];
  budget: number;
  persons: number;
  length: number;
  bedrooms: number;
  crew: boolean | null;
  priorities: string[];
  style: string | null;
  features: string[];
  brands: string[];
  name: string;
  email: string;
  phone: string;
  whatsapp: string;
  timeline: string;
  message: string;
}

// ─── STEPS ────────────────────────────────────────────────
const STEPS = [
  {
    key: "mode",
    overline: "Schritt 1",
    title: "Wie möchten Sie\nIhr Boot erleben?",
    bg: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=1920&h=1080&fit=crop",
  },
  {
    key: "lifestyle",
    overline: "Ihr Lifestyle",
    title: "Was beschreibt Sie\nam besten?",
    bg: "https://images.unsplash.com/photo-1540946485063-a40da27545f8?w=1920&h=1080&fit=crop",
  },
  {
    key: "region",
    overline: "Destination",
    title: "Wo zieht es\nSie hin?",
    bg: "https://images.unsplash.com/photo-1559494007-9f5847c49d94?w=1920&h=1080&fit=crop",
  },
  {
    key: "budget",
    overline: "Investment",
    title: "Ihr Budget",
    bg: "https://images.unsplash.com/photo-1621277224630-81a0a5df4a17?w=1920&h=1080&fit=crop",
  },
  {
    key: "details",
    overline: "Spezifikation",
    title: "Die Details\nIhres Bootes",
    bg: "https://images.unsplash.com/photo-1605281317010-fe5ffe798166?w=1920&h=1080&fit=crop",
  },
  {
    key: "priorities",
    overline: "Was zählt",
    title: "Ihre\nPrioritäten",
    bg: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=1920&h=1080&fit=crop",
  },
  {
    key: "style",
    overline: "Ästhetik",
    title: "Welcher Stil\nist Ihrer?",
    bg: "https://images.unsplash.com/photo-1540946485063-a40da27545f8?w=1920&h=1080&fit=crop",
  },
  {
    key: "features",
    overline: "Ausstattung",
    title: "Was darf\nnicht fehlen?",
    bg: "https://images.unsplash.com/photo-1621277224630-81a0a5df4a17?w=1920&h=1080&fit=crop",
  },
  {
    key: "brands",
    overline: "Präferenz",
    title: "Bevorzugte\nMarken",
    bg: "https://images.unsplash.com/photo-1559494007-9f5847c49d94?w=1920&h=1080&fit=crop",
  },
  {
    key: "contact",
    overline: "Fast geschafft",
    title: "Ihre\nKontaktdaten",
    bg: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=1920&h=1080&fit=crop",
  },
];

// ─── OPTIONS ──────────────────────────────────────────────
// ─── SVG ICON COMPONENT ──────────────────────────────────
function Icon({ name, className = "w-6 h-6" }: { name: string; className?: string }) {
  const icons: Record<string, JSX.Element> = {
    anchor: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 2a3 3 0 00-3 3c0 1.66 1.34 3 3 3s3-1.34 3-3-1.34-3-3-3zm0 6v14m0 0l-4-4m4 4l4-4M5 12H2m20 0h-3" /></svg>,
    sail: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 21l9-18 9 18H3zm9-18v18" /></svg>,
    cpu: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 3v2m6-2v2M9 19v2m6-2v2M3 9h2m-2 6h2m14-6h2m-2 6h2M7 7h10v10H7z" /></svg>,
    family: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" /></svg>,
    compass: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93A8.005 8.005 0 014.07 13H5v-1H4.07A8.005 8.005 0 0111 4.07V5h2V4.07A8.005 8.005 0 0119.93 11H19v2h.93A8.005 8.005 0 0113 19.93V19h-2v.93zM12 8l-4 8 4-2 4 2-4-8z" /></svg>,
    diamond: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2 9l4-5h12l4 5-10 13L2 9zm0 0h20M8 4l-2 5m10-5l2 5M12 4v5" /></svg>,
    bolt: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" /></svg>,
    sparkles: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z" /></svg>,
    briefcase: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M20.25 14.15v4.25c0 1.094-.787 2.036-1.872 2.18-2.087.277-4.216.42-6.378.42s-4.291-.143-6.378-.42c-1.085-.144-1.872-1.086-1.872-2.18v-4.25m16.5 0a2.18 2.18 0 00.75-1.661V8.706c0-1.081-.768-2.015-1.837-2.175a48.114 48.114 0 00-3.413-.387m4.5 8.006c-.194.165-.42.295-.673.38A23.978 23.978 0 0112 15.75c-2.648 0-5.195-.429-7.577-1.22a2.016 2.016 0 01-.673-.38m0 0A2.18 2.18 0 013 12.489V8.706c0-1.081.768-2.015 1.837-2.175a48.111 48.111 0 013.413-.387m7.5 0V5.25A2.25 2.25 0 0013.5 3h-3a2.25 2.25 0 00-2.25 2.25v.894m7.5 0a48.667 48.667 0 00-7.5 0M12 12.75h.008v.008H12v-.008z" /></svg>,
    globe: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" /></svg>,
    crown: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2 17l3-10 5 4 2-8 2 8 5-4 3 10H2z" /></svg>,
    sofa: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 12V8a3 3 0 013-3h8a3 3 0 013 3v4M3 12h18v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4zm3 6v2m12-2v2" /></svg>,
    leaf: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 21c-4-4-8-7-8-12a8 8 0 0116 0c0 5-4 8-8 12zm0-12v8m-3-5l3 3 3-3" /></svg>,
    palette: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M4.098 19.902a3.75 3.75 0 005.304 0l6.401-6.402M6.75 21A3.75 3.75 0 013 17.25V4.125C3 3.504 3.504 3 4.125 3h5.25c.621 0 1.125.504 1.125 1.125v4.072M6.75 21a3.75 3.75 0 003.75-3.75V8.197M6.75 21h13.125c.621 0 1.125-.504 1.125-1.125v-5.25c0-.621-.504-1.125-1.125-1.125h-4.072M10.5 8.197l2.88-2.88c.438-.439 1.15-.439 1.59 0l3.712 3.713c.44.44.44 1.152 0 1.59l-2.879 2.88M6.75 17.25h.008v.008H6.75v-.008z" /></svg>,
    music: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2z" /></svg>,
    users: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" /></svg>,
    ruler: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 21h18M3 21V3m0 18l4-4V3m14 18V7l-4-4H7" /></svg>,
    bed: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2 17v-5a3 3 0 013-3h14a3 3 0 013 3v5M2 17v2m20-2v2M6 9V7a2 2 0 012-2h2a2 2 0 012 2v2" /></svg>,
    captain: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" /></svg>,
    water: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2 13c2-3 4-3 6 0s4 3 6 0 4-3 6 0M2 17c2-3 4-3 6 0s4 3 6 0 4-3 6 0" /></svg>,
    helicopter: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 6h18M12 6v4m-4 0h8l2 5H6l2-5m4 5v4m-3 0h6" /></svg>,
    home: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" /></svg>,
    car: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 17h14M5 17a2 2 0 01-2-2V9l3-5h12l3 5v6a2 2 0 01-2 2M5 17a2 2 0 002 2h10a2 2 0 002-2M7 13h.01M17 13h.01" /></svg>,
    swim: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M2 20c2-2 4-2 6 0s4 2 6 0 4-2 6 0M12 4a2 2 0 100 4 2 2 0 000-4zM8 14l4-4 4 4" /></svg>,
    fire: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 6.471 6.471 0 009 11.5a3.5 3.5 0 006.362-6.286z" /></svg>,
    dumbbell: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 7h-1a1 1 0 00-1 1v8a1 1 0 001 1h1M18 7h1a1 1 0 011 1v8a1 1 0 01-1 1h-1M6 7v10M18 7v10M6 12h12M3 10v4m18-4v4" /></svg>,
    film: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3.375 19.5h17.25m-17.25 0a1.125 1.125 0 01-1.125-1.125M3.375 19.5h1.5C5.496 19.5 6 18.996 6 18.375m-3.75 0V5.625m0 12.75v-1.5c0-.621.504-1.125 1.125-1.125m18.375 2.625V5.625m0 12.75c0 .621-.504 1.125-1.125 1.125m1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125m0 3.75h-1.5A1.125 1.125 0 0118 18.375M20.625 4.5H3.375m17.25 0c.621 0 1.125.504 1.125 1.125M20.625 4.5h-1.5C18.504 4.5 18 5.004 18 5.625m3.75 0v1.5c0 .621-.504 1.125-1.125 1.125M3.375 4.5c-.621 0-1.125.504-1.125 1.125M3.375 4.5h1.5C5.496 4.5 6 5.004 6 5.625m-3.75 0v1.5c0 .621.504 1.125 1.125 1.125m0 0h1.5m-1.5 0c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125m1.5-3.75C5.496 8.25 6 7.746 6 7.125v-1.5M4.875 8.25C5.496 8.25 6 8.754 6 9.375v1.5m0-5.25v5.25m0-5.25C6 5.004 6.504 4.5 7.125 4.5h9.75c.621 0 1.125.504 1.125 1.125m1.125 2.625h1.5m-1.5 0A1.125 1.125 0 0118 7.125v-1.5m1.125 2.625c-.621 0-1.125.504-1.125 1.125v1.5m2.625-2.625c.621 0 1.125.504 1.125 1.125v1.5c0 .621-.504 1.125-1.125 1.125M18 5.625v5.25M7.125 12h9.75m-9.75 0A1.125 1.125 0 016 10.875M7.125 12C6.504 12 6 12.504 6 13.125m0-2.25C6 11.496 5.496 12 4.875 12M18 10.875c0 .621-.504 1.125-1.125 1.125M18 10.875c0 .621.504 1.125 1.125 1.125m-2.25 0c.621 0 1.125.504 1.125 1.125m-12 5.25v-5.25m0 5.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125m-12 0v-1.5c0-.621-.504-1.125-1.125-1.125M18 18.375v-5.25m0 5.25v-1.5c0-.621.504-1.125 1.125-1.125M18 13.125v1.5c0 .621.504 1.125 1.125 1.125M18 13.125c0-.621.504-1.125 1.125-1.125M6 13.125v1.5c0 .621-.504 1.125-1.125 1.125M6 13.125C6 12.504 5.496 12 4.875 12m-1.5 0h1.5m-1.5 0c-.621 0-1.125-.504-1.125-1.125v-1.5c0-.621.504-1.125 1.125-1.125m1.5 3.75c-.621 0-1.125-.504-1.125-1.125v-1.5" /></svg>,
    satellite: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M7.5 3.75H6A2.25 2.25 0 003.75 6v1.5M16.5 3.75H18A2.25 2.25 0 0120.25 6v1.5m0 9V18A2.25 2.25 0 0118 20.25h-1.5m-9 0H6A2.25 2.25 0 013.75 18v-1.5M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
    bulb: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 18v-5.25m0 0a6.01 6.01 0 001.5-.189m-1.5.189a6.01 6.01 0 01-1.5-.189m3.75 7.478a12.06 12.06 0 01-4.5 0m3.75 2.383a14.406 14.406 0 01-3 0M14.25 18v-.192c0-.983.658-1.823 1.508-2.316a7.5 7.5 0 10-7.517 0c.85.493 1.509 1.333 1.509 2.316V18" /></svg>,
    sun: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" /></svg>,
    umbrella: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m0-18C6.477 3 2 7.477 2 12h10m0-9c5.523 0 10 4.477 10 9H12m0 0v5a2 2 0 004 0" /></svg>,
    map: <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 6.75V15m6-6v8.25m.503 3.498l4.875-2.437c.381-.19.622-.58.622-1.006V4.82c0-.836-.88-1.38-1.628-1.006l-3.869 1.934c-.317.159-.69.159-1.006 0L9.503 3.252a1.125 1.125 0 00-1.006 0L3.622 5.689C3.24 5.88 3 6.27 3 6.695V19.18c0 .836.88 1.38 1.628 1.006l3.869-1.934c.317-.159.69-.159 1.006 0l4.994 2.497c.317.158.69.158 1.006 0z" /></svg>,
  };
  return icons[name] || <span className={className} />;
}

const MODES = [
  { key: "BUY", label: "Kaufen", sub: "Ihr eigenes Boot", icon: "anchor" },
  { key: "CHARTER", label: "Chartern", sub: "Luxus auf Zeit", icon: "sail" },
  { key: "CONSULT", label: "Beraten lassen", sub: "KI hilft Ihnen", icon: "cpu" },
];

const LIFESTYLES = [
  { key: "FAMILY", label: "Family", icon: "family", img: "https://images.unsplash.com/photo-1559494007-9f5847c49d94?w=600&h=400&fit=crop" },
  { key: "ADVENTURE", label: "Adventure", icon: "compass", img: "https://images.unsplash.com/photo-1605281317010-fe5ffe798166?w=600&h=400&fit=crop" },
  { key: "LUXURY", label: "Luxury", icon: "diamond", img: "https://images.unsplash.com/photo-1621277224630-81a0a5df4a17?w=600&h=400&fit=crop" },
  { key: "SPORT", label: "Sport", icon: "bolt", img: "https://images.unsplash.com/photo-1605281317010-fe5ffe798166?w=600&h=400&fit=crop" },
  { key: "PARTY", label: "Party", icon: "sparkles", img: "https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=600&h=400&fit=crop" },
  { key: "BUSINESS", label: "Business", icon: "briefcase", img: "https://images.unsplash.com/photo-1621277224630-81a0a5df4a17?w=600&h=400&fit=crop" },
  { key: "EXPLORE", label: "Exploration", icon: "globe", img: "https://images.unsplash.com/photo-1540946485063-a40da27545f8?w=600&h=400&fit=crop" },
];

const REGIONS = [
  { key: "MONACO", label: "Monaco & Côte d'Azur", code: "MC" },
  { key: "IBIZA", label: "Ibiza & Balearen", code: "ES" },
  { key: "GREECE", label: "Griechenland", code: "GR" },
  { key: "CROATIA", label: "Kroatien", code: "HR" },
  { key: "DUBAI", label: "Dubai", code: "AE" },
  { key: "CARIBBEAN", label: "Karibik", code: "CR" },
  { key: "MALDIVES", label: "Malediven", code: "MV" },
  { key: "MIAMI", label: "Miami & Florida", code: "US" },
  { key: "NORDSEE", label: "Nord- & Ostsee", code: "DE" },
  { key: "WORLDWIDE", label: "Weltreise", code: "WW" },
];

const PRIORITIES = [
  { key: "PRESTIGE", label: "Prestige", icon: "crown" },
  { key: "COMFORT", label: "Komfort", icon: "sofa" },
  { key: "SPEED", label: "Speed", icon: "bolt" },
  { key: "LUXURY", label: "Luxus", icon: "diamond" },
  { key: "SUSTAINABILITY", label: "Nachhaltigkeit", icon: "leaf" },
  { key: "DESIGN", label: "Design", icon: "palette" },
  { key: "TECHNOLOGY", label: "Technologie", icon: "cpu" },
  { key: "PARTY_P", label: "Entertainment", icon: "music" },
  { key: "FAMILY_P", label: "Familie", icon: "family" },
];

const STYLES = [
  { key: "MODERN", label: "Modern", gradient: "from-gray-100 to-stone-200", dark: false },
  { key: "FUTURISTIC", label: "Futuristisch", gradient: "from-violet-900 to-slate-900", dark: true },
  { key: "MONACO_L", label: "Monaco Luxury", gradient: "from-amber-200 to-yellow-100", dark: false },
  { key: "MINIMAL", label: "Minimalistisch", gradient: "from-sky-50 to-blue-100", dark: false },
  { key: "SPORTY", label: "Sportlich", gradient: "from-red-900 to-gray-900", dark: true },
  { key: "CLASSIC", label: "Klassisch", gradient: "from-amber-800 to-yellow-700", dark: true },
];

const FEATURES = [
  { key: "JACUZZI", label: "Jacuzzi", icon: "water" },
  { key: "HELIPAD", label: "Helipad", icon: "helicopter" },
  { key: "SMART", label: "Smart Home", icon: "home" },
  { key: "JETSKI_G", label: "Jetski Garage", icon: "car" },
  { key: "POOL", label: "Pool", icon: "swim" },
  { key: "SAUNA", label: "Sauna", icon: "fire" },
  { key: "GYM", label: "Gym", icon: "dumbbell" },
  { key: "CINEMA", label: "Kino", icon: "film" },
  { key: "SOUND", label: "Soundsystem", icon: "music" },
  { key: "STARLINK", label: "Starlink", icon: "satellite" },
  { key: "LED_UW", label: "Unterwasser-LED", icon: "bulb" },
  { key: "SOLAR", label: "Solaranlage", icon: "sun" },
  { key: "BEACH", label: "Beach Club", icon: "umbrella" },
];

const BRANDS = [
  { key: "LURSSEN", label: "Lürssen", country: "DE", tier: "Ultra" },
  { key: "FEADSHIP", label: "Feadship", country: "NL", tier: "Ultra" },
  { key: "BENETTI", label: "Benetti", country: "IT", tier: "Ultra" },
  { key: "SUNSEEKER", label: "Sunseeker", country: "GB", tier: "Premium" },
  { key: "AZIMUT", label: "Azimut", country: "IT", tier: "Premium" },
  { key: "PRINCESS", label: "Princess", country: "GB", tier: "Premium" },
  { key: "FERRETTI", label: "Ferretti", country: "IT", tier: "Premium" },
  { key: "PERSHING", label: "Pershing", country: "IT", tier: "Premium" },
  { key: "RIVA", label: "Riva", country: "IT", tier: "Premium" },
  { key: "LAGOON", label: "Lagoon", country: "FR", tier: "Sail" },
  { key: "BENETEAU", label: "Beneteau", country: "FR", tier: "Sail" },
  { key: "HANSE", label: "Hanse", country: "DE", tier: "Sail" },
  { key: "SEARAY", label: "Sea Ray", country: "US", tier: "Sport" },
  { key: "BAYLINER", label: "Bayliner", country: "US", tier: "Sport" },
  { key: "YAMAHA", label: "Yamaha", country: "JP", tier: "Sport" },
];

const TIMELINES = [
  "Sofort", "1–3 Monate", "3–6 Monate", "Innerhalb 1 Jahr", "Nur informieren",
];

// ─── HELPERS ──────────────────────────────────────────────
function fmt(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)} Mio. €`;
  if (n >= 1000) return `${Math.round(n / 1000)}K €`;
  return `${n} €`;
}

function sliderToValue(s: number): number {
  return Math.round(Math.exp(Math.log(500) + (s / 100) * (Math.log(100000000) - Math.log(500))));
}
function valueToSlider(v: number): number {
  return ((Math.log(v) - Math.log(500)) / (Math.log(100000000) - Math.log(500))) * 100;
}

function budgetTier(v: number): string {
  if (v < 10000) return "Einsteiger";
  if (v < 50000) return "Freizeit";
  if (v < 200000) return "Komfort";
  if (v < 1000000) return "Premium";
  if (v < 5000000) return "Luxury";
  if (v < 20000000) return "Super Luxury";
  return "Ultra Luxury";
}

// ═══════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════
export default function MatchingExperience() {
  const [step, setStep] = useState(0);
  const [dir, setDir] = useState(1);
  const [done, setDone] = useState(false);
  const [c, setC] = useState<Config>({
    mode: null, lifestyle: null, regions: [], budget: 250000,
    persons: 6, length: 15, bedrooms: 3, crew: null,
    priorities: [], style: null, features: [], brands: [],
    name: "", email: "", phone: "", whatsapp: "", timeline: "", message: "",
  });

  const up = (p: Partial<Config>) => setC((prev) => ({ ...prev, ...p }));
  const tog = (f: keyof Config, k: string) => {
    const a = c[f] as string[];
    up({ [f]: a.includes(k) ? a.filter((x) => x !== k) : [...a, k] });
  };
  const next = () => { if (step < STEPS.length - 1) { setDir(1); setStep(step + 1); } };
  const back = () => { if (step > 0) { setDir(-1); setStep(step - 1); } };

  const canNext = (): boolean => {
    const k = STEPS[step].key;
    if (k === "mode") return !!c.mode;
    if (k === "lifestyle") return !!c.lifestyle;
    if (k === "region") return c.regions.length > 0;
    if (k === "priorities") return c.priorities.length > 0;
    if (k === "contact") return !!(c.name && c.email);
    return true;
  };

  // AI sidebar text
  const aiText = (): string => {
    if (!c.lifestyle && !c.mode) return "Erzählen Sie mir von sich — ich finde Ihr perfektes Boot.";
    if (c.budget < 15000) return "Für Ihr Budget empfehle ich kompakte Sportboote oder einen Charter-Einstieg — perfekt zum Ausprobieren.";
    if (c.budget < 100000) return "Gute Wahl — in diesem Segment finden Sie bereits hochwertige Day Cruiser und Segelboote.";
    if (c.budget < 500000) return "Premium-Segment — erwarten Sie Vollausstattung, Flybridge und individuelle Anpassungen.";
    if (c.budget < 5000000) return "Luxury-Segment — ich verbinde Sie mit exklusiven Werften und Brokern weltweit.";
    return "Ultra Luxury — für Sie kommt nur das Beste in Frage. Individuelle Megayacht-Projekte erwarten Sie.";
  };

  // ─── DONE ───────────────────────────────────────────────
  if (done) {
    return (
      <div className="fixed inset-0 bg-[#050508] flex items-center justify-center">
        <div className="absolute inset-0">
          <img src="https://images.unsplash.com/photo-1567899378494-47b22a2ae96a?w=1920&h=1080&fit=crop" className="w-full h-full object-cover opacity-15" alt="" />
          <div className="absolute inset-0 bg-gradient-to-t from-[#050508] via-[#050508]/70 to-[#050508]/90" />
        </div>
        <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 1 }} className="relative text-center px-6 max-w-lg">
          <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 0.3, type: "spring" }}
            className="w-24 h-24 mx-auto mb-10 rounded-full bg-gradient-to-br from-amber-300 to-amber-600 flex items-center justify-center shadow-2xl shadow-amber-500/20">
            <svg className="w-12 h-12 text-black" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" /></svg>
          </motion.div>
          <h1 className="text-5xl font-extralight mb-4 tracking-tight" style={{ fontFamily: "'Playfair Display', serif" }}>Vielen Dank.</h1>
          <p className="text-gray-400 text-base mb-2">Ihre Yacht-Matching Experience wurde erfolgreich übermittelt.</p>
          <p className="text-amber-400/60 text-sm mb-12">Unsere Experten analysieren Ihre Wünsche und melden sich innerhalb von 24h.</p>
          <Link href="/" className="inline-flex items-center gap-3 px-10 py-4 rounded-full bg-gradient-to-r from-amber-400 to-amber-600 text-black font-medium hover:shadow-xl hover:shadow-amber-500/20 transition-all">
            Zurück zur Startseite <span>→</span>
          </Link>
        </motion.div>
      </div>
    );
  }

  // ─── RENDER STEP CONTENT ────────────────────────────────
  const renderContent = () => {
    const k = STEPS[step].key;

    if (k === "mode") return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 max-w-3xl w-full">
        {MODES.map((m) => (
          <button key={m.key} onClick={() => up({ mode: m.key })}
            className={`group relative p-8 md:p-10 rounded-3xl border-2 text-center transition-all duration-700 backdrop-blur-sm ${
              c.mode === m.key
                ? "border-amber-400/60 bg-amber-500/[0.08] shadow-2xl shadow-amber-500/10 scale-[1.02]"
                : "border-white/[0.06] bg-white/[0.02] hover:border-white/[0.15] hover:bg-white/[0.04]"
            }`}>
            <span className="block mb-5 transition-transform duration-500 group-hover:scale-110 text-amber-400/80"><Icon name={m.icon} className="w-12 h-12 md:w-14 md:h-14 mx-auto" /></span>
            <span className="text-white text-xl md:text-2xl font-light block mb-2" style={{ fontFamily: "'Playfair Display', serif" }}>{m.label}</span>
            <span className="text-gray-500 text-sm">{m.sub}</span>
            {c.mode === m.key && (
              <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }}
                className="absolute top-4 right-4 w-7 h-7 rounded-full bg-gradient-to-br from-amber-400 to-amber-600 flex items-center justify-center shadow-lg">
                <svg className="w-4 h-4 text-black" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>
              </motion.div>
            )}
          </button>
        ))}
      </div>
    );

    if (k === "lifestyle") return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 max-w-4xl w-full">
        {LIFESTYLES.map((l) => (
          <button key={l.key} onClick={() => up({ lifestyle: l.key })}
            className={`group relative rounded-3xl overflow-hidden aspect-[3/4] border-2 transition-all duration-700 ${
              c.lifestyle === l.key ? "border-amber-400 shadow-2xl shadow-amber-500/15 scale-[1.03]" : "border-transparent hover:border-white/15 hover:scale-[1.01]"
            }`}>
            <img src={l.img} alt={l.label} className="absolute inset-0 w-full h-full object-cover transition-transform duration-1000 group-hover:scale-115" />
            <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-black/20 to-transparent" />
            <div className="absolute bottom-0 left-0 right-0 p-5">
              <span className="block mb-2 text-amber-400/70"><Icon name={l.icon} className="w-5 h-5" /></span>
              <span className="text-white text-sm font-medium">{l.label}</span>
            </div>
            {c.lifestyle === l.key && <GoldCheck />}
          </button>
        ))}
      </div>
    );

    if (k === "region") return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 max-w-4xl w-full">
        {REGIONS.map((r) => (
          <button key={r.key} onClick={() => tog("regions", r.key)}
            className={`p-5 rounded-2xl border text-left transition-all duration-300 backdrop-blur-sm ${
              c.regions.includes(r.key)
                ? "border-amber-400/60 bg-amber-500/10"
                : "border-white/[0.06] bg-white/[0.03] hover:border-white/[0.12]"
            }`}>
            <span className="text-amber-400/60 text-xs font-mono tracking-wider block mb-2">{r.code}</span>
            <span className="text-white text-xs font-medium block">{r.label}</span>
          </button>
        ))}
        <p className="col-span-full text-center text-gray-600 text-xs mt-2">Mehrfachauswahl möglich</p>
      </div>
    );

    if (k === "budget") return (
      <div className="max-w-2xl w-full">
        <div className="text-center mb-14">
          <motion.span key={c.budget} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
            className="text-7xl md:text-8xl lg:text-[10rem] font-extralight bg-gradient-to-r from-amber-200 via-amber-400 to-amber-600 bg-clip-text text-transparent block mb-4 leading-none"
            style={{ fontFamily: "'Playfair Display', serif" }}>
            {fmt(c.budget)}
          </motion.span>
          <motion.span key={budgetTier(c.budget)} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="inline-block px-6 py-2 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 text-sm tracking-[0.2em] uppercase">
            {budgetTier(c.budget)}
          </motion.span>
        </div>
        <input type="range" min={0} max={100} step={0.5} value={valueToSlider(c.budget)}
          onChange={(e) => up({ budget: sliderToValue(parseFloat(e.target.value)) })}
          className="w-full h-1 rounded-full appearance-none cursor-pointer bg-white/10 mb-4
            [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-6 [&::-webkit-slider-thumb]:h-6
            [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-gradient-to-br
            [&::-webkit-slider-thumb]:from-amber-300 [&::-webkit-slider-thumb]:to-amber-600
            [&::-webkit-slider-thumb]:shadow-lg [&::-webkit-slider-thumb]:shadow-amber-500/30
            [&::-webkit-slider-thumb]:cursor-pointer" />
        <div className="flex justify-between text-[10px] text-gray-600 mb-8">
          <span>500 €</span><span>50K €</span><span>500K €</span><span>5M €</span><span>100M €</span>
        </div>
        <div className="flex flex-wrap justify-center gap-2">
          {[5000, 25000, 100000, 500000, 2000000, 10000000, 50000000].map((v) => (
            <button key={v} onClick={() => up({ budget: v })}
              className={`px-4 py-2 rounded-full text-xs transition-all ${
                Math.abs(c.budget - v) < v * 0.1
                  ? "bg-amber-500/10 text-amber-400 border border-amber-400/30"
                  : "text-gray-500 border border-white/[0.06] hover:border-white/[0.12]"
              }`}>
              {fmt(v)}
            </button>
          ))}
        </div>
      </div>
    );

    if (k === "details") return (
      <div className="max-w-lg w-full space-y-8">
        <Slider label="Personen" icon="users" value={c.persons} min={1} max={50} suffix="" onChange={(v) => up({ persons: v })} />
        <Slider label="Bootslänge" icon="ruler" value={c.length} min={3} max={100} suffix="m" onChange={(v) => up({ length: v })} />
        <Slider label="Kabinen" icon="bed" value={c.bedrooms} min={0} max={15} suffix="" onChange={(v) => up({ bedrooms: v })} />
        <div className="flex items-center justify-between p-5 rounded-2xl border border-white/[0.06] bg-white/[0.03] backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <span className="text-amber-400/60"><Icon name="captain" className="w-5 h-5" /></span>
            <span className="text-white text-sm">Crew benötigt?</span>
          </div>
          <div className="flex gap-2">
            {[{ v: true, l: "Ja" }, { v: false, l: "Nein" }].map((o) => (
              <button key={String(o.v)} onClick={() => up({ crew: o.v })}
                className={`px-5 py-2 rounded-full text-sm transition-all ${
                  c.crew === o.v ? "bg-amber-500/10 text-amber-400 border border-amber-400/30" : "text-gray-500 border border-white/[0.06]"
                }`}>{o.l}</button>
            ))}
          </div>
        </div>
      </div>
    );

    if (k === "priorities") return (
      <div className="grid grid-cols-3 gap-3 max-w-xl w-full">
        {PRIORITIES.map((p) => (
          <button key={p.key} onClick={() => { if (c.priorities.includes(p.key) || c.priorities.length < 3) tog("priorities", p.key); }}
            className={`p-5 rounded-2xl border text-center transition-all duration-300 ${
              c.priorities.includes(p.key) ? "border-amber-400/60 bg-amber-500/10" : "border-white/[0.06] bg-white/[0.03] hover:border-white/[0.12]"
            }`}>
            <span className="block mb-3 text-amber-400/70"><Icon name={p.icon} className="w-7 h-7 mx-auto" /></span>
            <span className="text-white text-xs font-medium">{p.label}</span>
          </button>
        ))}
        <p className="col-span-full text-center text-gray-600 text-xs">{c.priorities.length}/3 ausgewählt</p>
      </div>
    );

    if (k === "style") return (
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4 max-w-3xl w-full">
        {STYLES.map((s) => (
          <button key={s.key} onClick={() => up({ style: s.key })}
            className={`group relative rounded-2xl overflow-hidden border-2 transition-all duration-500 ${
              c.style === s.key ? "border-amber-400 shadow-lg shadow-amber-500/10" : "border-transparent hover:border-white/10"
            }`}>
            <div className={`h-32 bg-gradient-to-br ${s.gradient} transition-transform duration-700 group-hover:scale-105`} />
            <div className="p-4 bg-black/40 backdrop-blur-sm">
              <span className={`text-sm font-medium ${s.dark ? "text-white" : "text-white"}`}>{s.label}</span>
            </div>
            {c.style === s.key && <GoldCheck />}
          </button>
        ))}
      </div>
    );

    if (k === "features") return (
      <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-5 gap-3 max-w-3xl w-full">
        {FEATURES.map((f) => (
          <button key={f.key} onClick={() => tog("features", f.key)}
            className={`p-4 rounded-2xl border text-center transition-all duration-300 ${
              c.features.includes(f.key) ? "border-amber-400/60 bg-amber-500/10" : "border-white/[0.06] bg-white/[0.03] hover:border-white/[0.12]"
            }`}>
            <span className="block mb-2 text-amber-400/70"><Icon name={f.icon} className="w-6 h-6 mx-auto" /></span>
            <span className="text-white text-[10px] font-medium">{f.label}</span>
          </button>
        ))}
      </div>
    );

    if (k === "brands") return (
      <div className="grid grid-cols-3 sm:grid-cols-5 gap-3 max-w-3xl w-full">
        {BRANDS.map((b) => (
          <button key={b.key} onClick={() => tog("brands", b.key)}
            className={`p-4 rounded-2xl border text-center transition-all duration-300 ${
              c.brands.includes(b.key) ? "border-amber-400/60 bg-amber-500/10" : "border-white/[0.06] bg-white/[0.03] hover:border-white/[0.12]"
            }`}>
            <span className="text-amber-400/50 text-[9px] font-mono tracking-wider block mb-1">{b.country}</span>
            <span className="text-white text-xs font-medium block">{b.label}</span>
            <span className={`text-[9px] mt-0.5 block ${
              b.tier === "Ultra" ? "text-amber-400" : b.tier === "Premium" ? "text-sky-400" : "text-gray-500"
            }`}>{b.tier}</span>
          </button>
        ))}
      </div>
    );

    if (k === "contact") return (
      <div className="max-w-md w-full space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <Input label="Name *" value={c.name} onChange={(v) => up({ name: v })} placeholder="Max Mustermann" />
          <Input label="E-Mail *" value={c.email} onChange={(v) => up({ email: v })} placeholder="max@mail.de" type="email" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <Input label="Telefon" value={c.phone} onChange={(v) => up({ phone: v })} placeholder="+49 170 123..." type="tel" />
          <Input label="WhatsApp" value={c.whatsapp} onChange={(v) => up({ whatsapp: v })} placeholder="+49 170 123..." type="tel" />
        </div>
        <div>
          <label className="block text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-2">Zeitraum</label>
          <div className="flex flex-wrap gap-2">
            {TIMELINES.map((t) => (
              <button key={t} onClick={() => up({ timeline: t })}
                className={`px-4 py-2 rounded-full text-xs transition-all ${
                  c.timeline === t ? "bg-amber-500/10 text-amber-400 border border-amber-400/30" : "text-gray-500 border border-white/[0.06]"
                }`}>{t}</button>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-2">Nachricht</label>
          <textarea value={c.message} onChange={(e) => up({ message: e.target.value })} rows={3}
            className="w-full px-4 py-3 rounded-xl bg-white/[0.03] border border-white/[0.06] text-white text-sm placeholder-gray-700 focus:border-amber-400/30 outline-none resize-none"
            placeholder="Besondere Wünsche..." />
        </div>
        <button onClick={() => setDone(true)} disabled={!c.name || !c.email}
          className="w-full py-4 rounded-xl bg-gradient-to-r from-amber-400 to-amber-600 text-black font-semibold text-sm hover:shadow-xl hover:shadow-amber-500/20 disabled:opacity-30 transition-all flex items-center justify-center gap-2">
          Matching starten <span>→</span>
        </button>
        <p className="text-center text-gray-700 text-[9px]">Unverbindlich · Kostenlos · DSGVO-konform</p>
      </div>
    );

    return null;
  };

  const s = STEPS[step];

  // ═══ MAIN LAYOUT ═══════════════════════════════════════
  return (
    <div className="fixed inset-0 bg-[#050508]">
      {/* ─── Background image (fullscreen, per step) ─── */}
      <AnimatePresence mode="wait">
        <motion.div key={step} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 1 }}
          className="absolute inset-0">
          <img src={s.bg} alt="" className="w-full h-full object-cover opacity-30" />
          <div className="absolute inset-0 bg-[#050508]/50" />
          <div className="absolute inset-0 bg-gradient-to-t from-[#050508] via-[#050508]/40 to-[#050508]/70" />
        </motion.div>
      </AnimatePresence>

      {/* ─── Top bar ─── */}
      <div className="absolute top-0 left-0 right-0 z-50 px-6 py-5 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-300/80 to-amber-600/80 flex items-center justify-center">
            <span className="text-black text-xs font-bold">BC</span>
          </div>
        </Link>
        <div className="flex items-center gap-6">
          {/* Progress dots */}
          <div className="hidden md:flex items-center gap-1.5">
            {STEPS.map((_, i) => (
              <div key={i} className={`rounded-full transition-all duration-500 ${
                i < step ? "w-1.5 h-1.5 bg-amber-500" : i === step ? "w-6 h-1.5 bg-amber-400" : "w-1.5 h-1.5 bg-white/10"
              }`} />
            ))}
          </div>
          <span className="text-gray-600 text-xs font-mono">{String(step + 1).padStart(2, "0")}/{String(STEPS.length).padStart(2, "0")}</span>
        </div>
      </div>

      {/* ─── Main content area ─── */}
      <div className="absolute inset-0 flex items-start justify-center px-6 pt-16 pb-20 overflow-y-auto">
        <AnimatePresence mode="wait" custom={dir}>
          <motion.div key={step} custom={dir}
            initial={{ opacity: 0, x: dir * 80 }}
            animate={{ opacity: 1, x: 0, transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] } }}
            exit={{ opacity: 0, x: dir * -40, transition: { duration: 0.3 } }}
            className="flex flex-col items-center w-full pt-12 pb-8"
          >
            {/* Overline */}
            <motion.p initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
              className="text-amber-400 text-xs tracking-[0.35em] uppercase mb-6 flex items-center gap-3">
              <span className="w-8 h-px bg-amber-400/50" />
              {s.overline}
              <span className="w-8 h-px bg-amber-400/50" />
            </motion.p>

            {/* Title */}
            <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2, duration: 0.7 }}
              className="text-4xl md:text-6xl lg:text-7xl font-light text-white text-center mb-8 tracking-tight whitespace-pre-line leading-[1.1] drop-shadow-[0_2px_30px_rgba(0,0,0,0.8)]"
              style={{ fontFamily: "'Playfair Display', serif" }}>
              {s.title}
            </motion.h1>

            {/* Content */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }} className="w-full flex justify-center">
              {renderContent()}
            </motion.div>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* ─── AI Concierge bubble ─── */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.2, duration: 0.8 }}
        className="fixed bottom-32 right-8 max-w-[280px] z-40 hidden lg:block">
        <div className="p-5 rounded-2xl bg-black/30 backdrop-blur-2xl border border-white/[0.06] shadow-2xl">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-amber-400 to-amber-600 flex items-center justify-center shadow-lg shadow-amber-500/20">
              <Icon name="cpu" className="w-4 h-4 text-black" />
            </div>
            <div>
              <span className="text-amber-400/80 text-[10px] tracking-[0.2em] uppercase block">AI Concierge</span>
              <span className="text-green-400/60 text-[8px] flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400/60 animate-pulse" />
                Aktiv
              </span>
            </div>
          </div>
          <AnimatePresence mode="wait">
            <motion.p key={aiText()} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="text-gray-300 text-sm leading-relaxed font-light">{aiText()}</motion.p>
          </AnimatePresence>
        </div>
        {/* Speech bubble pointer */}
        <div className="absolute -bottom-2 right-10 w-4 h-4 rotate-45 bg-black/30 backdrop-blur-2xl border-r border-b border-white/[0.06]" />
      </motion.div>

      {/* ─── Bottom nav ─── */}
      <div className="fixed bottom-0 left-0 right-0 z-50 px-8 py-6 flex items-center justify-between backdrop-blur-xl bg-[#050508]/40">
        <button onClick={back} disabled={step === 0}
          className="flex items-center gap-2 px-7 py-3 rounded-full border border-white/[0.08] text-gray-400 text-sm font-light hover:text-white hover:border-white/[0.15] disabled:opacity-10 transition-all duration-500">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
          Zurück
        </button>
        {step < STEPS.length - 1 && (
          <button onClick={next} disabled={!canNext()}
            className="group flex items-center gap-3 px-10 py-3.5 rounded-full bg-gradient-to-r from-amber-400 to-amber-600 text-black font-semibold text-sm hover:shadow-2xl hover:shadow-amber-500/25 disabled:opacity-20 transition-all duration-500">
            Weiter
            <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" /></svg>
          </button>
        )}
      </div>

      {/* ─── Progress bar ─── */}
      <div className="fixed bottom-0 left-0 right-0 z-40 h-[2px] bg-white/[0.04]">
        <motion.div className="h-full bg-gradient-to-r from-amber-400 to-amber-600"
          animate={{ width: `${((step + 1) / STEPS.length) * 100}%` }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
      </div>
    </div>
  );
}

// ═══ SUB-COMPONENTS ═══════════════════════════════════════
function Pill({ active, onClick, left, title, sub }: { active: boolean; onClick: () => void; left: React.ReactNode; title: string; sub: string }) {
  return (
    <button onClick={onClick}
      className={`w-full flex items-center p-5 rounded-2xl border transition-all duration-500 backdrop-blur-sm text-left ${
        active ? "border-amber-400/60 bg-amber-500/10 shadow-lg shadow-amber-500/5" : "border-white/[0.06] bg-white/[0.03] hover:border-white/[0.12]"
      }`}>
      {left}
      <div className="flex-1">
        <span className="text-white text-lg font-light block">{title}</span>
        <span className="text-gray-500 text-xs">{sub}</span>
      </div>
      {active && <div className="w-6 h-6 rounded-full bg-gradient-to-br from-amber-400 to-amber-600 flex items-center justify-center ml-3">
        <svg className="w-3.5 h-3.5 text-black" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>
      </div>}
    </button>
  );
}

function GoldCheck() {
  return (
    <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }}
      className="absolute top-3 right-3 w-7 h-7 rounded-full bg-gradient-to-br from-amber-400 to-amber-600 flex items-center justify-center shadow-lg">
      <svg className="w-4 h-4 text-black" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>
    </motion.div>
  );
}

function Slider({ label, icon, value, min, max, suffix, onChange }: {
  label: string; icon: string; value: number; min: number; max: number; suffix: string; onChange: (v: number) => void;
}) {
  return (
    <div className="p-5 rounded-2xl border border-white/[0.06] bg-white/[0.03] backdrop-blur-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <span className="text-amber-400/60"><Icon name={icon} className="w-5 h-5" /></span>
          <span className="text-white text-sm">{label}</span>
        </div>
        <span className="text-amber-400 font-medium text-lg" style={{ fontFamily: "'Playfair Display', serif" }}>{value}{suffix}</span>
      </div>
      <input type="range" min={min} max={max} value={value} onChange={(e) => onChange(parseInt(e.target.value))}
        className="w-full h-1 rounded-full appearance-none cursor-pointer bg-white/10
          [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-5 [&::-webkit-slider-thumb]:h-5
          [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-gradient-to-br
          [&::-webkit-slider-thumb]:from-amber-300 [&::-webkit-slider-thumb]:to-amber-600
          [&::-webkit-slider-thumb]:shadow-md [&::-webkit-slider-thumb]:shadow-amber-500/20
          [&::-webkit-slider-thumb]:cursor-pointer" />
    </div>
  );
}

function Input({ label, value, onChange, placeholder, type = "text" }: {
  label: string; value: string; onChange: (v: string) => void; placeholder: string; type?: string;
}) {
  return (
    <div>
      <label className="block text-[10px] text-gray-500 tracking-[0.2em] uppercase mb-2">{label}</label>
      <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className="w-full px-4 py-3 rounded-xl bg-white/[0.03] border border-white/[0.06] text-white text-sm placeholder-gray-700 focus:border-amber-400/30 outline-none transition-all" />
    </div>
  );
}
