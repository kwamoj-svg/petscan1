"use client";

import { useRef, useMemo } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { useYachtConfig, LIGHTING_PRESETS } from "@/hooks/useYachtConfig";

export default function OceanWater() {
  const meshRef = useRef<THREE.Mesh>(null);
  const { lightingMood } = useYachtConfig();
  const preset = LIGHTING_PRESETS[lightingMood];

  const shaderMaterial = useMemo(() => {
    return new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 },
        uWaterColor: { value: new THREE.Color(preset.waterColor) },
        uSunColor: { value: new THREE.Color(preset.sunColor) },
        uSunIntensity: { value: preset.sunIntensity },
      },
      vertexShader: `
        uniform float uTime;
        varying vec2 vUv;
        varying float vElevation;
        varying vec3 vWorldPos;
        varying vec3 vNormal;

        // Simplex-like noise hash
        vec3 hash3(vec2 p) {
          vec3 q = vec3(
            dot(p, vec2(127.1, 311.7)),
            dot(p, vec2(269.5, 183.3)),
            dot(p, vec2(419.2, 371.9))
          );
          return fract(sin(q) * 43758.5453);
        }

        float noise(vec2 p) {
          vec2 i = floor(p);
          vec2 f = fract(p);
          f = f * f * (3.0 - 2.0 * f);
          float a = dot(hash3(i).xy, vec2(1.0));
          float b = dot(hash3(i + vec2(1.0, 0.0)).xy, vec2(1.0));
          float c = dot(hash3(i + vec2(0.0, 1.0)).xy, vec2(1.0));
          float d = dot(hash3(i + vec2(1.0, 1.0)).xy, vec2(1.0));
          return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);
        }

        void main() {
          vUv = uv;
          vec3 pos = position;

          // Multi-octave ocean waves
          float wave = 0.0;

          // Large swells
          wave += sin(pos.x * 0.12 + uTime * 0.35) * 0.22;
          wave += sin(pos.z * 0.08 + uTime * 0.25) * 0.18;
          wave += sin((pos.x * 0.7 + pos.z * 0.5) * 0.1 + uTime * 0.4) * 0.12;

          // Medium waves
          wave += sin(pos.x * 0.4 + pos.z * 0.3 + uTime * 0.7) * 0.06;
          wave += sin(pos.x * 0.6 - pos.z * 0.2 + uTime * 0.55) * 0.04;

          // Small ripples (noise-based)
          float ripple = noise(pos.xz * 0.8 + uTime * 0.15) * 0.03;
          ripple += noise(pos.xz * 1.5 + uTime * 0.25) * 0.015;

          wave += ripple;
          pos.y += wave;
          vElevation = wave;

          // Compute displaced normal for lighting
          float eps = 0.1;
          float hL = sin((pos.x - eps) * 0.12 + uTime * 0.35) * 0.22 + sin(pos.z * 0.08 + uTime * 0.25) * 0.18;
          float hR = sin((pos.x + eps) * 0.12 + uTime * 0.35) * 0.22 + sin(pos.z * 0.08 + uTime * 0.25) * 0.18;
          float hD = sin(pos.x * 0.12 + uTime * 0.35) * 0.22 + sin((pos.z - eps) * 0.08 + uTime * 0.25) * 0.18;
          float hU = sin(pos.x * 0.12 + uTime * 0.35) * 0.22 + sin((pos.z + eps) * 0.08 + uTime * 0.25) * 0.18;
          vNormal = normalize(vec3(hL - hR, 2.0 * eps, hD - hU));

          vWorldPos = (modelMatrix * vec4(pos, 1.0)).xyz;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(pos, 1.0);
        }
      `,
      fragmentShader: `
        uniform vec3 uWaterColor;
        uniform vec3 uSunColor;
        uniform float uSunIntensity;
        uniform float uTime;
        varying vec2 vUv;
        varying float vElevation;
        varying vec3 vWorldPos;
        varying vec3 vNormal;

        void main() {
          // Deep vs shallow color
          float depth = smoothstep(-0.3, 0.35, vElevation);
          vec3 deepColor = uWaterColor * 0.2;
          vec3 shallowColor = uWaterColor * 1.8;
          vec3 color = mix(deepColor, shallowColor, depth);

          // Fresnel effect (stronger reflection at grazing angles)
          vec3 viewDir = normalize(cameraPosition - vWorldPos);
          float fresnel = pow(1.0 - max(dot(viewDir, vNormal), 0.0), 3.5);
          fresnel = clamp(fresnel, 0.0, 1.0);

          // Sun reflection / specular highlight
          vec3 sunDir = normalize(vec3(10.0, 15.0, 5.0));
          vec3 reflectDir = reflect(-sunDir, vNormal);
          float spec = pow(max(dot(viewDir, reflectDir), 0.0), 128.0) * uSunIntensity * 0.35;

          // Sun color influence
          vec3 sunReflection = uSunColor * spec;

          // Sky reflection via fresnel
          vec3 skyColor = mix(uWaterColor * 0.5, uSunColor * 0.3, 0.3);
          color = mix(color, skyColor, fresnel * 0.5);
          color += sunReflection;

          // Foam on wave peaks
          float foam = smoothstep(0.22, 0.35, vElevation);
          foam *= 0.2;
          color += vec3(foam);

          // Subtle caustic-like sparkle
          float sparkle = pow(max(sin(vWorldPos.x * 8.0 + uTime * 2.0) * sin(vWorldPos.z * 6.0 + uTime * 1.5), 0.0), 16.0) * 0.08;
          color += vec3(sparkle) * uSunColor;

          // Distance fade to horizon
          float dist = length(vUv - 0.5) * 2.0;
          float horizonFade = smoothstep(0.6, 1.0, dist);
          color = mix(color, uWaterColor * 0.15, horizonFade * 0.5);

          // Final alpha — more opaque overall, slight transparency at edges
          float alpha = mix(0.92, 0.7, horizonFade);

          gl_FragColor = vec4(color, alpha);
        }
      `,
      transparent: true,
      side: THREE.DoubleSide,
    });
  }, [preset.waterColor, preset.sunColor, preset.sunIntensity]);

  useFrame((state) => {
    if (shaderMaterial) {
      shaderMaterial.uniforms.uTime.value = state.clock.elapsedTime;
      shaderMaterial.uniforms.uWaterColor.value.lerp(
        new THREE.Color(preset.waterColor),
        0.03
      );
      shaderMaterial.uniforms.uSunColor.value.lerp(
        new THREE.Color(preset.sunColor),
        0.03
      );
      shaderMaterial.uniforms.uSunIntensity.value +=
        (preset.sunIntensity - shaderMaterial.uniforms.uSunIntensity.value) * 0.03;
    }
  });

  return (
    <mesh
      ref={meshRef}
      rotation={[-Math.PI / 2, 0, 0]}
      position={[0, -0.8, 0]}
      material={shaderMaterial}
      receiveShadow
    >
      <planeGeometry args={[120, 120, 200, 200]} />
    </mesh>
  );
}
