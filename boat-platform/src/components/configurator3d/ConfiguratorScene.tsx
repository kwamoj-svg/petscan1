"use client";

import { Suspense, useRef, useEffect, useMemo } from "react";
import { Canvas, useThree, useFrame } from "@react-three/fiber";
import { OrbitControls, Environment, Stars, Float } from "@react-three/drei";
import * as THREE from "three";
import YachtModel from "./YachtModel";
import OceanWater from "./OceanWater";
import { useYachtConfig, LIGHTING_PRESETS } from "@/hooks/useYachtConfig";

function SceneLighting() {
  const dirLightRef = useRef<THREE.DirectionalLight>(null);
  const fillLightRef = useRef<THREE.DirectionalLight>(null);
  const { lightingMood } = useYachtConfig();
  const preset = LIGHTING_PRESETS[lightingMood];

  useFrame(() => {
    if (dirLightRef.current) {
      dirLightRef.current.color.lerp(new THREE.Color(preset.sunColor), 0.04);
      dirLightRef.current.intensity += (preset.sunIntensity - dirLightRef.current.intensity) * 0.04;
    }
    if (fillLightRef.current) {
      fillLightRef.current.color.lerp(new THREE.Color(preset.ambientColor), 0.04);
    }
  });

  return (
    <>
      {/* Ambient base */}
      <ambientLight color={preset.ambientColor} intensity={preset.ambientIntensity} />

      {/* Main sun / key light */}
      <directionalLight
        ref={dirLightRef}
        position={[12, 18, 8]}
        color={preset.sunColor}
        intensity={preset.sunIntensity}
        castShadow
        shadow-mapSize={[2048, 2048]}
        shadow-camera-far={60}
        shadow-camera-left={-15}
        shadow-camera-right={15}
        shadow-camera-top={15}
        shadow-camera-bottom={-15}
        shadow-bias={-0.0005}
      />

      {/* Fill light (opposite side for softer shadows) */}
      <directionalLight
        ref={fillLightRef}
        position={[-8, 10, -5]}
        color={preset.ambientColor}
        intensity={preset.sunIntensity * 0.2}
      />

      {/* Rim / backlight for dramatic edge lighting */}
      <directionalLight
        position={[-5, 8, -12]}
        color="#6688bb"
        intensity={0.4}
      />

      {/* Water bounce light from below */}
      <pointLight position={[0, -2, 0]} color="#4a7fa5" intensity={0.15} distance={15} />

      {/* Accent lights */}
      <pointLight position={[-6, 4, -6]} color="#4a6fa5" intensity={0.25} distance={20} />
      <pointLight position={[6, 3, 6]} color={preset.sunColor} intensity={0.15} distance={20} />
    </>
  );
}

function SceneBackground() {
  const { scene } = useThree();
  const { lightingMood } = useYachtConfig();
  const preset = LIGHTING_PRESETS[lightingMood];

  useFrame(() => {
    const targetColor = new THREE.Color(preset.bgColor);
    if (scene.background instanceof THREE.Color) {
      scene.background.lerp(targetColor, 0.025);
    } else {
      scene.background = targetColor.clone();
    }
    if (scene.fog instanceof THREE.FogExp2) {
      scene.fog.color.lerp(new THREE.Color(preset.fogColor), 0.025);
    }
  });

  useEffect(() => {
    scene.background = new THREE.Color(preset.bgColor);
    scene.fog = new THREE.FogExp2(preset.fogColor, 0.018);
  }, []);

  return null;
}

function CameraSetup() {
  const { camera } = useThree();

  useEffect(() => {
    camera.position.set(7, 3.5, 9);
    camera.lookAt(0, 0.5, 0);
  }, [camera]);

  return (
    <OrbitControls
      enableDamping
      dampingFactor={0.04}
      minDistance={4}
      maxDistance={25}
      maxPolarAngle={Math.PI / 2.05}
      minPolarAngle={0.2}
      autoRotate
      autoRotateSpeed={0.2}
      target={[0, 0.3, 0]}
      enablePan={false}
    />
  );
}

function LoadingFallback() {
  return (
    <Float speed={2} rotationIntensity={0.5}>
      <mesh position={[0, 0, 0]}>
        <octahedronGeometry args={[0.4, 2]} />
        <meshStandardMaterial color="#D4AF37" wireframe transparent opacity={0.6} />
      </mesh>
    </Float>
  );
}

// Horizon gradient mesh for more immersive sky feel
function HorizonSky() {
  const { lightingMood } = useYachtConfig();
  const preset = LIGHTING_PRESETS[lightingMood];
  const matRef = useRef<THREE.ShaderMaterial>(null);

  const skyMat = useMemo(
    () =>
      new THREE.ShaderMaterial({
        uniforms: {
          uTopColor: { value: new THREE.Color(preset.bgColor) },
          uBottomColor: { value: new THREE.Color(preset.fogColor).multiplyScalar(1.5) },
          uSunColor: { value: new THREE.Color(preset.sunColor) },
          uSunIntensity: { value: preset.sunIntensity },
        },
        vertexShader: `
        varying vec3 vWorldPosition;
        void main() {
          vec4 worldPos = modelMatrix * vec4(position, 1.0);
          vWorldPosition = worldPos.xyz;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
        fragmentShader: `
        uniform vec3 uTopColor;
        uniform vec3 uBottomColor;
        uniform vec3 uSunColor;
        uniform float uSunIntensity;
        varying vec3 vWorldPosition;

        void main() {
          float h = normalize(vWorldPosition).y;
          float t = max(h, 0.0);
          vec3 color = mix(uBottomColor, uTopColor, pow(t, 0.5));

          // Sun glow near horizon
          float sunGlow = pow(max(1.0 - t, 0.0), 4.0) * uSunIntensity * 0.1;
          color += uSunColor * sunGlow;

          gl_FragColor = vec4(color, 1.0);
        }
      `,
        side: THREE.BackSide,
      }),
    [preset]
  );

  useFrame(() => {
    if (skyMat.uniforms) {
      skyMat.uniforms.uTopColor.value.lerp(new THREE.Color(preset.bgColor), 0.02);
      skyMat.uniforms.uBottomColor.value.lerp(
        new THREE.Color(preset.fogColor).multiplyScalar(1.5),
        0.02
      );
      skyMat.uniforms.uSunColor.value.lerp(new THREE.Color(preset.sunColor), 0.02);
      skyMat.uniforms.uSunIntensity.value +=
        (preset.sunIntensity - skyMat.uniforms.uSunIntensity.value) * 0.02;
    }
  });

  return (
    <mesh material={skyMat}>
      <sphereGeometry args={[80, 32, 32]} />
    </mesh>
  );
}

export default function ConfiguratorScene() {
  return (
    <Canvas
      shadows
      dpr={[1, 2]}
      gl={{
        antialias: true,
        toneMapping: THREE.ACESFilmicToneMapping,
        toneMappingExposure: 1.1,
        alpha: false,
        powerPreference: "high-performance",
      }}
      camera={{ fov: 40, near: 0.1, far: 250, position: [7, 3.5, 9] }}
      className="!absolute inset-0"
    >
      <SceneBackground />
      <SceneLighting />
      <CameraSetup />

      <Suspense fallback={<LoadingFallback />}>
        <YachtModel />
        <OceanWater />
        <HorizonSky />
        <Stars
          radius={90}
          depth={60}
          count={2500}
          factor={3}
          saturation={0}
          fade
          speed={0.3}
        />
        <Environment preset="sunset" background={false} />
      </Suspense>
    </Canvas>
  );
}

