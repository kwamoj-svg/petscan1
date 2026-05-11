"use client";

import { useRef, useMemo } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { useYachtConfig, ACCENT_COLORS } from "@/hooks/useYachtConfig";

// ─── HULL PATH: Smooth superyacht profile using CatmullRom ────────────
function createHullGeometry(): THREE.BufferGeometry {
  // Define hull cross-sections at different longitudinal positions
  // Each section: [x-offset along length, halfBeam, height, keelDepth, deckFlare]
  const sections = [
    { z: -5.0, hb: 0.0, h: 0.0, keel: 0.0, flare: 0.0 },   // Stern tip
    { z: -4.8, hb: 0.3, h: 0.15, keel: 0.25, flare: 0.02 },
    { z: -4.4, hb: 0.9, h: 0.35, keel: 0.55, flare: 0.05 },
    { z: -3.8, hb: 1.2, h: 0.5, keel: 0.7, flare: 0.08 },
    { z: -3.0, hb: 1.35, h: 0.6, keel: 0.8, flare: 0.1 },
    { z: -2.0, hb: 1.4, h: 0.65, keel: 0.85, flare: 0.12 },
    { z: -1.0, hb: 1.42, h: 0.68, keel: 0.88, flare: 0.12 },
    { z: 0.0, hb: 1.42, h: 0.7, keel: 0.9, flare: 0.12 },
    { z: 1.0, hb: 1.4, h: 0.7, keel: 0.9, flare: 0.11 },
    { z: 2.0, hb: 1.35, h: 0.68, keel: 0.88, flare: 0.1 },
    { z: 3.0, hb: 1.2, h: 0.65, keel: 0.82, flare: 0.08 },
    { z: 3.8, hb: 0.95, h: 0.55, keel: 0.7, flare: 0.05 },
    { z: 4.3, hb: 0.6, h: 0.4, keel: 0.5, flare: 0.03 },
    { z: 4.7, hb: 0.25, h: 0.25, keel: 0.3, flare: 0.01 },
    { z: 5.0, hb: 0.0, h: 0.05, keel: 0.0, flare: 0.0 },    // Bow tip
  ];

  const radialSegments = 16; // around each cross section
  const lengthSegments = sections.length;
  const vertices: number[] = [];
  const indices: number[] = [];
  const normals: number[] = [];
  const uvs: number[] = [];

  // Generate cross-section rings
  for (let i = 0; i < lengthSegments; i++) {
    const s = sections[i];
    const v = i / (lengthSegments - 1);

    for (let j = 0; j <= radialSegments; j++) {
      const u = j / radialSegments;
      const angle = u * Math.PI; // Only bottom half (0 to PI) — this is a hull

      // Create smooth hull cross section
      const sinA = Math.sin(angle);
      const cosA = Math.cos(angle);

      // X position: beam with flare near top
      const flareFactor = Math.pow(Math.max(0, cosA), 0.5) * s.flare;
      const x = sinA * (s.hb + flareFactor);

      // Y position: hull depth below waterline
      const y = -cosA * s.keel;

      // Push vertex
      vertices.push(x, y, s.z);

      // Simple normal (will be recomputed)
      normals.push(sinA, -cosA * 0.5, 0);
      uvs.push(u, v);
    }
  }

  // Add deck surface (flat top)
  const deckStartIdx = vertices.length / 3;
  for (let i = 0; i < lengthSegments; i++) {
    const s = sections[i];
    const v = i / (lengthSegments - 1);
    // Port edge
    vertices.push(s.hb + s.flare, 0, s.z);
    normals.push(0, 1, 0);
    uvs.push(0, v);
    // Starboard edge
    vertices.push(-(s.hb + s.flare), 0, s.z);
    normals.push(0, 1, 0);
    uvs.push(1, v);
  }

  // Generate hull indices
  for (let i = 0; i < lengthSegments - 1; i++) {
    for (let j = 0; j < radialSegments; j++) {
      const a = i * (radialSegments + 1) + j;
      const b = a + radialSegments + 1;
      indices.push(a, b, a + 1);
      indices.push(a + 1, b, b + 1);
    }
  }

  // Generate deck indices
  for (let i = 0; i < lengthSegments - 1; i++) {
    const p0 = deckStartIdx + i * 2;
    const p1 = p0 + 1;
    const p2 = p0 + 2;
    const p3 = p0 + 3;
    indices.push(p0, p2, p1);
    indices.push(p1, p2, p3);
  }

  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.Float32BufferAttribute(vertices, 3));
  geometry.setAttribute("normal", new THREE.Float32BufferAttribute(normals, 3));
  geometry.setAttribute("uv", new THREE.Float32BufferAttribute(uvs, 2));
  geometry.setIndex(indices);
  geometry.computeVertexNormals();
  return geometry;
}

// ─── SUPERSTRUCTURE: Curved, modern superyacht cabin ─────────────────
function SuperstructureGeometry({ level }: { level: number }) {
  const geometry = useMemo(() => {
    // Each level gets progressively narrower and shorter
    const configs = [
      { width: 2.4, height: 0.85, length: 5.5, zOffset: -0.6, radius: 0.15 },  // Main salon
      { width: 2.0, height: 0.75, length: 4.0, zOffset: -1.0, radius: 0.12 },   // Upper deck
      { width: 1.5, height: 0.65, length: 2.2, zOffset: -1.8, radius: 0.1 },    // Bridge deck
    ];
    const c = configs[Math.min(level, configs.length - 1)];

    // Create a rounded box shape for modern yacht look
    const shape = new THREE.Shape();
    const r = c.radius;
    const hw = c.width / 2;
    const hh = c.height / 2;

    shape.moveTo(-hw + r, -hh);
    shape.lineTo(hw - r, -hh);
    shape.quadraticCurveTo(hw, -hh, hw, -hh + r);
    shape.lineTo(hw, hh - r);
    shape.quadraticCurveTo(hw, hh, hw - r, hh);
    shape.lineTo(-hw + r, hh);
    shape.quadraticCurveTo(-hw, hh, -hw, hh - r);
    shape.lineTo(-hw, -hh + r);
    shape.quadraticCurveTo(-hw, -hh, -hw + r, -hh);

    const extrudeSettings: THREE.ExtrudeGeometryOptions = {
      steps: 1,
      depth: c.length,
      bevelEnabled: true,
      bevelThickness: 0.06,
      bevelSize: 0.06,
      bevelSegments: 4,
    };

    const geo = new THREE.ExtrudeGeometry(shape, extrudeSettings);
    geo.rotateX(Math.PI / 2);
    geo.translate(0, 0, c.zOffset + c.length / 2);
    return geo;
  }, [level]);

  return <primitive object={geometry} attach="geometry" />;
}

// ─── WINDOW STRIP ────────────────────────────────────────────────────
function WindowStrip({
  position,
  width,
  height,
  length,
  side,
}: {
  position: [number, number, number];
  width: number;
  height: number;
  length: number;
  side: "port" | "starboard" | "front" | "back";
}) {
  const glassMat = useMemo(
    () =>
      new THREE.MeshPhysicalMaterial({
        color: new THREE.Color("#88ccff"),
        transparent: true,
        opacity: 0.25,
        metalness: 0.2,
        roughness: 0.02,
        transmission: 0.92,
        thickness: 0.05,
        envMapIntensity: 2.0,
      }),
    []
  );

  if (side === "front" || side === "back") {
    return (
      <mesh position={position} material={glassMat}>
        <boxGeometry args={[width, height, 0.02]} />
      </mesh>
    );
  }

  const xSign = side === "port" ? 1 : -1;
  // Create continuous window band
  return (
    <mesh
      position={[position[0] * xSign, position[1], position[2]]}
      material={glassMat}
    >
      <boxGeometry args={[0.02, height, length]} />
    </mesh>
  );
}

// ─── RAILING SYSTEM ──────────────────────────────────────────────────
function Railings({
  accentMat,
  zStart,
  zEnd,
  xOffset,
  yBase,
  railHeight = 0.5,
}: {
  accentMat: THREE.Material;
  zStart: number;
  zEnd: number;
  xOffset: number;
  yBase: number;
  railHeight?: number;
}) {
  const count = Math.floor(Math.abs(zEnd - zStart) / 0.45);
  const posts = useMemo(() => {
    const arr: [number, number, number][] = [];
    for (let i = 0; i <= count; i++) {
      const z = zStart + (zEnd - zStart) * (i / count);
      arr.push([xOffset, yBase + railHeight / 2, z]);
    }
    return arr;
  }, [count, zStart, zEnd, xOffset, yBase, railHeight]);

  return (
    <group>
      {/* Vertical posts */}
      {posts.map((pos, i) => (
        <mesh key={i} position={pos} material={accentMat}>
          <cylinderGeometry args={[0.012, 0.012, railHeight, 6]} />
        </mesh>
      ))}
      {/* Top horizontal rail */}
      <mesh
        position={[xOffset, yBase + railHeight, (zStart + zEnd) / 2]}
        material={accentMat}
      >
        <boxGeometry args={[0.025, 0.025, Math.abs(zEnd - zStart)]} />
      </mesh>
      {/* Mid horizontal rail */}
      <mesh
        position={[xOffset, yBase + railHeight * 0.5, (zStart + zEnd) / 2]}
        material={accentMat}
      >
        <boxGeometry args={[0.018, 0.018, Math.abs(zEnd - zStart)]} />
      </mesh>
    </group>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN YACHT MODEL
// ═══════════════════════════════════════════════════════════════════════
export default function YachtModel() {
  const groupRef = useRef<THREE.Group>(null);
  const { hullColor, hullMaterial, deckMaterial, accentColor, features } =
    useYachtConfig();

  // Gentle float + subtle roll
  useFrame((state) => {
    if (groupRef.current) {
      const t = state.clock.elapsedTime;
      groupRef.current.position.y = Math.sin(t * 0.4) * 0.06;
      groupRef.current.rotation.z = Math.sin(t * 0.25) * 0.008;
      groupRef.current.rotation.x = Math.sin(t * 0.35 + 0.5) * 0.003;
    }
  });

  // ─── Materials ────────────────────────────────────────────────
  const hullMat = useMemo(() => {
    return new THREE.MeshPhysicalMaterial({
      color: new THREE.Color(hullColor),
      metalness: hullMaterial === "carbon" ? 0.85 : hullMaterial === "glossy" ? 0.25 : 0.08,
      roughness: hullMaterial === "matte" ? 0.75 : hullMaterial === "carbon" ? 0.25 : 0.1,
      clearcoat: hullMaterial === "glossy" ? 1.0 : hullMaterial === "carbon" ? 0.8 : 0.2,
      clearcoatRoughness: 0.05,
      envMapIntensity: 2.0,
      reflectivity: 0.9,
    });
  }, [hullColor, hullMaterial]);

  const deckMat = useMemo(() => {
    const colors = { teak: "#9B7B3D", white: "#E8E4DB", dark: "#252525" };
    return new THREE.MeshStandardMaterial({
      color: new THREE.Color(colors[deckMaterial]),
      roughness: deckMaterial === "teak" ? 0.85 : 0.35,
      metalness: 0.02,
    });
  }, [deckMaterial]);

  const accentMat = useMemo(() => {
    const hex = ACCENT_COLORS[accentColor];
    return new THREE.MeshPhysicalMaterial({
      color: new THREE.Color(hex),
      metalness: 0.95,
      roughness: 0.1,
      clearcoat: 0.5,
      envMapIntensity: 2.5,
    });
  }, [accentColor]);

  const glassMat = useMemo(
    () =>
      new THREE.MeshPhysicalMaterial({
        color: new THREE.Color("#88ccff"),
        transparent: true,
        opacity: 0.2,
        metalness: 0.15,
        roughness: 0.02,
        transmission: 0.95,
        thickness: 0.05,
        envMapIntensity: 3.0,
      }),
    []
  );

  const darkMat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: "#1a1a1a",
        roughness: 0.6,
        metalness: 0.3,
      }),
    []
  );

  const lightMat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: "#E8E0D0",
        roughness: 0.5,
        metalness: 0.05,
      }),
    []
  );

  const hullGeo = useMemo(() => createHullGeometry(), []);

  return (
    <group ref={groupRef} position={[0, 0, 0]} scale={0.55}>
      {/* ═══ HULL ═══ */}
      <mesh geometry={hullGeo} material={hullMat} castShadow receiveShadow />

      {/* ═══ HULL STRIPE (waterline accent) ═══ */}
      <mesh material={accentMat} position={[0, -0.05, 0]}>
        <torusGeometry args={[1.42, 0.018, 8, 64, Math.PI]} />
        {/* A subtle stripe is hard with torus, use box strips instead */}
      </mesh>

      {/* Waterline stripes — port & starboard */}
      {[1, -1].map((side) => (
        <mesh key={`wl${side}`} material={accentMat} position={[side * 1.38, -0.1, -0.3]}>
          <boxGeometry args={[0.025, 0.04, 8.5]} />
        </mesh>
      ))}

      {/* ═══ MAIN DECK FLOOR ═══ */}
      <mesh material={deckMat} position={[0, 0.02, 0]} receiveShadow>
        <boxGeometry args={[2.7, 0.04, 9.5]} />
      </mesh>

      {/* Forward deck teak planking texture effect (subtle lines) */}
      {Array.from({ length: 8 }).map((_, i) => (
        <mesh key={`plank${i}`} position={[0, 0.045, 2.5 + i * 0.25]} material={darkMat}>
          <boxGeometry args={[2.2, 0.002, 0.01]} />
        </mesh>
      ))}

      {/* ═══ SUPERSTRUCTURE — Level 0: Main Salon ═══ */}
      <group position={[0, 0.46, 0]}>
        <mesh material={hullMat} castShadow>
          <SuperstructureGeometry level={0} />
        </mesh>
        {/* Continuous window bands — both sides */}
        <WindowStrip position={[1.21, 0.1, -0.6]} width={0} height={0.4} length={4.8} side="port" />
        <WindowStrip position={[1.21, 0.1, -0.6]} width={0} height={0.4} length={4.8} side="starboard" />
        {/* Rear window */}
        <WindowStrip position={[0, 0.1, -3.4]} width={2.0} height={0.4} length={0} side="back" />
      </group>

      {/* ═══ SUPERSTRUCTURE — Level 1: Upper Deck ═══ */}
      <group position={[0, 1.35, 0]}>
        <mesh material={hullMat} castShadow>
          <SuperstructureGeometry level={1} />
        </mesh>
        {/* Upper deck floor */}
        <mesh material={deckMat} position={[0, -0.38, -1.0]} receiveShadow>
          <boxGeometry args={[2.2, 0.04, 4.5]} />
        </mesh>
        {/* Window bands */}
        <WindowStrip position={[1.01, 0.05, -1.0]} width={0} height={0.35} length={3.5} side="port" />
        <WindowStrip position={[1.01, 0.05, -1.0]} width={0} height={0.35} length={3.5} side="starboard" />
      </group>

      {/* ═══ SUPERSTRUCTURE — Level 2: Bridge ═══ */}
      <group position={[0, 2.15, 0]}>
        <mesh material={hullMat} castShadow>
          <SuperstructureGeometry level={2} />
        </mesh>
        {/* Panoramic bridge windows — wraparound */}
        <WindowStrip position={[0, 0.05, -0.68]} width={1.35} height={0.4} length={0} side="front" />
        <WindowStrip position={[0.76, 0.05, -1.8]} width={0} height={0.4} length={1.8} side="port" />
        <WindowStrip position={[0.76, 0.05, -1.8]} width={0} height={0.4} length={1.8} side="starboard" />
      </group>

      {/* ═══ FLYBRIDGE DECK ═══ */}
      <mesh material={deckMat} position={[0, 2.85, -1.6]} receiveShadow>
        <boxGeometry args={[1.7, 0.04, 2.8]} />
      </mesh>

      {/* Flybridge arch/hardtop */}
      <group position={[0, 3.15, -1.6]}>
        {/* Support pillars */}
        {[[-0.7, 0, 1.0], [0.7, 0, 1.0], [-0.7, 0, -0.8], [0.7, 0, -0.8]].map((pos, i) => (
          <mesh key={`fp${i}`} material={accentMat} position={pos as [number, number, number]}>
            <cylinderGeometry args={[0.025, 0.035, 0.6, 8]} />
          </mesh>
        ))}
        {/* Hardtop canopy */}
        <mesh material={hullMat} position={[0, 0.32, 0.1]}>
          <boxGeometry args={[1.6, 0.04, 2.2]} />
        </mesh>
      </group>

      {/* ═══ MAST & RADAR ═══ */}
      <group position={[0, 3.5, -1.6]}>
        {/* Main mast */}
        <mesh material={accentMat}>
          <cylinderGeometry args={[0.025, 0.035, 1.2, 8]} />
        </mesh>
        {/* Radar dome */}
        <mesh position={[0, 0.7, 0]} material={lightMat}>
          <sphereGeometry args={[0.12, 16, 12]} />
        </mesh>
        {/* Radar arm */}
        <mesh position={[0, 0.5, 0]} material={accentMat}>
          <boxGeometry args={[1.0, 0.02, 0.06]} />
        </mesh>
        {/* Navigation lights */}
        <mesh position={[0, 0.85, 0]}>
          <sphereGeometry args={[0.03, 8, 8]} />
          <meshStandardMaterial color="#ff3333" emissive="#ff3333" emissiveIntensity={0.5} />
        </mesh>
      </group>

      {/* ═══ BOW — Sleek pointed bow ═══ */}
      <group position={[0, -0.1, 4.8]}>
        {/* Bow bulb (subtle) */}
        <mesh material={hullMat} castShadow>
          <sphereGeometry args={[0.15, 12, 12]} />
        </mesh>
        {/* Bow sprit */}
        <mesh material={accentMat} position={[0, 0.25, 0.4]} rotation={[Math.PI / 6, 0, 0]}>
          <cylinderGeometry args={[0.015, 0.02, 1.0, 6]} />
        </mesh>
      </group>

      {/* ═══ ANCHOR ═══ */}
      <group position={[0.8, 0.15, 4.0]}>
        <mesh material={accentMat}>
          <boxGeometry args={[0.08, 0.15, 0.03]} />
        </mesh>
      </group>

      {/* ═══ STERN / TRANSOM ═══ */}
      <group position={[0, 0, -5.0]}>
        {/* Swim platform */}
        <mesh material={deckMat} position={[0, -0.35, -0.3]} receiveShadow>
          <boxGeometry args={[2.4, 0.06, 0.8]} />
        </mesh>
        {/* Steps down to swim platform */}
        {[0, 1, 2].map((i) => (
          <mesh key={`step${i}`} material={deckMat} position={[0, -0.1 - i * 0.1, -0.1 - i * 0.15]}>
            <boxGeometry args={[1.2, 0.04, 0.2]} />
          </mesh>
        ))}
        {/* Stern accent trim */}
        <mesh material={accentMat} position={[0, 0.3, -0.05]}>
          <boxGeometry args={[2.5, 0.03, 0.03]} />
        </mesh>
      </group>

      {/* ═══ RAILINGS — Port & Starboard ═══ */}
      <Railings accentMat={accentMat} zStart={-4.0} zEnd={4.0} xOffset={1.4} yBase={0.04} railHeight={0.45} />
      <Railings accentMat={accentMat} zStart={-4.0} zEnd={4.0} xOffset={-1.4} yBase={0.04} railHeight={0.45} />

      {/* Upper deck railings */}
      <Railings accentMat={accentMat} zStart={-2.8} zEnd={1.0} xOffset={1.15} yBase={0.97} railHeight={0.38} />
      <Railings accentMat={accentMat} zStart={-2.8} zEnd={1.0} xOffset={-1.15} yBase={0.97} railHeight={0.38} />

      {/* Flybridge railings */}
      <Railings accentMat={accentMat} zStart={-2.8} zEnd={-0.3} xOffset={0.85} yBase={2.85} railHeight={0.3} />
      <Railings accentMat={accentMat} zStart={-2.8} zEnd={-0.3} xOffset={-0.85} yBase={2.85} railHeight={0.3} />

      {/* ═══ EXHAUST VENTS ═══ */}
      {[0.5, -0.5].map((x) => (
        <mesh key={`exhaust${x}`} material={darkMat} position={[x, 0.9, -3.3]}>
          <cylinderGeometry args={[0.06, 0.06, 0.08, 12]} />
        </mesh>
      ))}

      {/* ═══ CLEATS (mooring) ═══ */}
      {[
        [1.4, 0.08, 3.5], [1.4, 0.08, 1.0], [1.4, 0.08, -2.5],
        [-1.4, 0.08, 3.5], [-1.4, 0.08, 1.0], [-1.4, 0.08, -2.5],
      ].map((pos, i) => (
        <mesh key={`cleat${i}`} material={accentMat} position={pos as [number, number, number]}>
          <boxGeometry args={[0.04, 0.03, 0.12]} />
        </mesh>
      ))}

      {/* ═══ NAVIGATION LIGHTS ═══ */}
      {/* Port = Red, Starboard = Green */}
      <mesh position={[1.35, 0.5, 3.0]}>
        <sphereGeometry args={[0.025, 8, 8]} />
        <meshStandardMaterial color="#ff0000" emissive="#ff0000" emissiveIntensity={0.8} />
      </mesh>
      <mesh position={[-1.35, 0.5, 3.0]}>
        <sphereGeometry args={[0.025, 8, 8]} />
        <meshStandardMaterial color="#00ff00" emissive="#00ff00" emissiveIntensity={0.8} />
      </mesh>

      {/* ═══ TENDER GARAGE DOORS (stern) ═══ */}
      <mesh material={darkMat} position={[0, 0.25, -4.95]}>
        <boxGeometry args={[1.6, 0.5, 0.03]} />
      </mesh>

      {/* ═══ OPTIONAL FEATURES ═══ */}

      {/* ── JACUZZI (Flybridge) ── */}
      {features.jacuzzi && (
        <group position={[0, 2.9, -0.8]}>
          {/* Outer shell */}
          <mesh castShadow>
            <cylinderGeometry args={[0.55, 0.6, 0.28, 32]} />
            <meshPhysicalMaterial color="#E8E0D0" roughness={0.5} metalness={0.05} />
          </mesh>
          {/* Water */}
          <mesh position={[0, 0.08, 0]}>
            <cylinderGeometry args={[0.48, 0.48, 0.15, 32]} />
            <meshPhysicalMaterial
              color="#1a6b8a"
              transparent
              opacity={0.55}
              roughness={0.02}
              transmission={0.6}
              thickness={0.2}
            />
          </mesh>
          {/* Rim */}
          <mesh position={[0, 0.14, 0]} material={accentMat}>
            <torusGeometry args={[0.52, 0.025, 8, 32]} />
          </mesh>
          {/* LED ring */}
          <mesh position={[0, -0.12, 0]}>
            <torusGeometry args={[0.55, 0.01, 6, 32]} />
            <meshStandardMaterial color="#4A9BD9" emissive="#4A9BD9" emissiveIntensity={0.4} />
          </mesh>
        </group>
      )}

      {/* ── HELIPAD (Bow area) ── */}
      {features.helipad && (
        <group position={[0, 0.06, 3.0]}>
          {/* Pad surface */}
          <mesh rotation={[-Math.PI / 2, 0, 0]} receiveShadow>
            <circleGeometry args={[0.9, 32]} />
            <meshStandardMaterial color="#2a2a2a" roughness={0.9} />
          </mesh>
          {/* H marking */}
          <group position={[0, 0.005, 0]} rotation={[-Math.PI / 2, 0, 0]}>
            <mesh>
              <boxGeometry args={[0.08, 0.5, 0.01]} />
              <meshStandardMaterial color="#D4AF37" emissive="#D4AF37" emissiveIntensity={0.3} />
            </mesh>
            <mesh position={[0.2, 0, 0]}>
              <boxGeometry args={[0.08, 0.5, 0.01]} />
              <meshStandardMaterial color="#D4AF37" emissive="#D4AF37" emissiveIntensity={0.3} />
            </mesh>
            <mesh position={[-0.2, 0, 0]}>
              <boxGeometry args={[0.08, 0.5, 0.01]} />
              <meshStandardMaterial color="#D4AF37" emissive="#D4AF37" emissiveIntensity={0.3} />
            </mesh>
            <mesh>
              <boxGeometry args={[0.5, 0.08, 0.01]} />
              <meshStandardMaterial color="#D4AF37" emissive="#D4AF37" emissiveIntensity={0.3} />
            </mesh>
          </group>
          {/* Outer circle */}
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.005, 0]}>
            <ringGeometry args={[0.7, 0.75, 32]} />
            <meshStandardMaterial color="#D4AF37" emissive="#D4AF37" emissiveIntensity={0.25} />
          </mesh>
          {/* Corner lights */}
          {[
            [0.75, 0.04, 0], [-0.75, 0.04, 0],
            [0, 0.04, 0.75], [0, 0.04, -0.75],
          ].map((pos, i) => (
            <mesh key={`hlight${i}`} position={pos as [number, number, number]}>
              <sphereGeometry args={[0.025, 8, 8]} />
              <meshStandardMaterial color="#ffcc00" emissive="#ffcc00" emissiveIntensity={0.6} />
            </mesh>
          ))}
        </group>
      )}

      {/* ── SUNBATHING AREA (Bow) ── */}
      {features.sunbathing && (
        <group position={[0, 0.06, 2.8]}>
          {/* Main sunpad */}
          <mesh receiveShadow>
            <boxGeometry args={[1.8, 0.12, 1.6]} />
            <meshStandardMaterial color="#E8DCC8" roughness={0.7} />
          </mesh>
          {/* Headrest */}
          <mesh position={[0, 0.12, -0.65]} rotation={[0.3, 0, 0]}>
            <boxGeometry args={[1.4, 0.08, 0.5]} />
            <meshStandardMaterial color="#D4C9B0" roughness={0.75} />
          </mesh>
          {/* Accent stitching lines */}
          {[-0.5, 0, 0.5].map((x) => (
            <mesh key={`stitch${x}`} position={[x, 0.065, 0]} material={accentMat}>
              <boxGeometry args={[0.01, 0.005, 1.4]} />
            </mesh>
          ))}
        </group>
      )}

      {/* ── INFINITY POOL (Main deck aft) ── */}
      {features.pool && (
        <group position={[0, 0.06, -3.5]}>
          {/* Pool shell */}
          <mesh castShadow>
            <boxGeometry args={[1.8, 0.35, 2.0]} />
            <meshPhysicalMaterial color="#E8E4DB" roughness={0.4} metalness={0.05} />
          </mesh>
          {/* Water */}
          <mesh position={[0, 0.1, 0]}>
            <boxGeometry args={[1.6, 0.2, 1.8]} />
            <meshPhysicalMaterial
              color="#0a7ea8"
              transparent
              opacity={0.5}
              roughness={0.01}
              transmission={0.8}
              thickness={0.3}
            />
          </mesh>
          {/* LED underwater lights */}
          {[-0.6, 0, 0.6].map((z) => (
            <mesh key={`plight${z}`} position={[0, -0.05, z]}>
              <sphereGeometry args={[0.03, 8, 8]} />
              <meshStandardMaterial color="#00ccff" emissive="#00ccff" emissiveIntensity={0.5} />
            </mesh>
          ))}
          {/* Pool edge trim */}
          <mesh position={[0, 0.18, 0]} material={accentMat}>
            <boxGeometry args={[1.85, 0.02, 2.05]} />
          </mesh>
        </group>
      )}

      {/* ═══ DECK FURNITURE ═══ */}
      {/* Aft lounge area */}
      <group position={[0, 0.06, -3.8]}>
        {!features.pool && (
          <>
            {/* L-shaped sofa */}
            <mesh position={[0, 0.15, 0]}>
              <boxGeometry args={[2.0, 0.2, 0.6]} />
              <meshStandardMaterial color="#D4C9B0" roughness={0.7} />
            </mesh>
            <mesh position={[0.85, 0.15, 0.5]}>
              <boxGeometry args={[0.35, 0.2, 1.0]} />
              <meshStandardMaterial color="#D4C9B0" roughness={0.7} />
            </mesh>
            {/* Coffee table */}
            <mesh position={[0, 0.2, 0.6]} material={darkMat}>
              <boxGeometry args={[0.8, 0.05, 0.5]} />
            </mesh>
            <mesh position={[0, 0.1, 0.6]} material={accentMat}>
              <cylinderGeometry args={[0.03, 0.03, 0.15, 8]} />
            </mesh>
          </>
        )}
      </group>

      {/* ═══ UNDERWATER HULL LIGHTING ═══ */}
      {[
        [0.8, -0.6, -2], [-0.8, -0.6, -2],
        [0.8, -0.6, 0], [-0.8, -0.6, 0],
        [0.8, -0.6, 2], [-0.8, -0.6, 2],
      ].map((pos, i) => (
        <pointLight
          key={`uhlight${i}`}
          position={pos as [number, number, number]}
          color="#4A9BD9"
          intensity={0.15}
          distance={2}
        />
      ))}
    </group>
  );
}
