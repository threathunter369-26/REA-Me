import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { SectionInfo } from '../types/reverseEngineering';
import { Maximize2, RotateCcw, Eye, Layers } from 'lucide-react';

interface BinaryStructure3DProps {
  sections: SectionInfo[];
  entropyChunks: { offset: number; entropy: number; sectionName: string }[];
  fileName: string;
}

export const BinaryStructure3D: React.FC<BinaryStructure3DProps> = ({
  sections,
  entropyChunks,
  fileName,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hoveredSection, setHoveredSection] = useState<string | null>(null);
  const [wireframe, setWireframe] = useState<boolean>(false);
  const [autoRotate, setAutoRotate] = useState<boolean>(true);

  const sceneRef = useRef<THREE.Scene | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const materialsRef = useRef<THREE.MeshStandardMaterial[]>([]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight || 340;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    sceneRef.current = scene;
    scene.background = new THREE.Color(0x0a0c10);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 18, 38);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    rendererRef.current = renderer;
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // Ambient and directional lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
    scene.add(ambientLight);

    const dirLight1 = new THREE.DirectionalLight(0x60a5fa, 1.2);
    dirLight1.position.set(20, 30, 20);
    scene.add(dirLight1);

    const dirLight2 = new THREE.DirectionalLight(0xa855f7, 0.9);
    dirLight2.position.set(-20, -20, -10);
    scene.add(dirLight2);

    // Ground Grid
    const gridHelper = new THREE.GridHelper(50, 25, 0x334155, 0x1e293b);
    gridHelper.position.y = -4;
    scene.add(gridHelper);

    // Group for sections & entropy landscape
    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // Render 3D Section Blocks
    const totalSections = sections.length;
    const spacing = 6.5;
    const startX = -((totalSections - 1) * spacing) / 2;
    materialsRef.current = [];

    sections.forEach((sec, idx) => {
      const x = startX + idx * spacing;
      const height = Math.max(1.5, (sec.entropy / 8) * 8);
      const isHighEntropy = sec.entropy > 7.0;

      // Color coding: High entropy (packed/encrypted) -> Red/Orange, Code -> Blue, Data -> Emerald
      let baseColor = 0x3b82f6;
      if (sec.permissions.execute && !isHighEntropy) baseColor = 0x6366f1;
      else if (isHighEntropy) baseColor = 0xef4444;
      else if (sec.permissions.write) baseColor = 0x10b981;
      else baseColor = 0x8b5cf6;

      const geometry = new THREE.BoxGeometry(4.2, height, 4.2);
      const material = new THREE.MeshStandardMaterial({
        color: baseColor,
        roughness: 0.25,
        metalness: 0.6,
        wireframe,
        transparent: true,
        opacity: 0.88,
      });
      materialsRef.current.push(material);

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(x, -4 + height / 2, 0);
      mesh.userData = { section: sec.name, entropy: sec.entropy, address: sec.virtualAddress };
      mainGroup.add(mesh);

      // Section top cap indicator
      const capGeo = new THREE.BoxGeometry(4.25, 0.25, 4.25);
      const capMat = new THREE.MeshBasicMaterial({
        color: isHighEntropy ? 0xfca5a5 : 0x93c5fd,
      });
      const capMesh = new THREE.Mesh(capGeo, capMat);
      capMesh.position.set(x, -4 + height + 0.12, 0);
      mainGroup.add(capMesh);
    });

    // Render 3D Entropy Curve / Ribbon
    if (entropyChunks && entropyChunks.length > 1) {
      const curvePoints: THREE.Vector3[] = [];
      const ribbonWidth = (totalSections * spacing) + 4;
      const step = ribbonWidth / (entropyChunks.length - 1);
      const ribbonStartX = -ribbonWidth / 2;

      entropyChunks.forEach((chunk, i) => {
        const px = ribbonStartX + i * step;
        const py = -4 + (chunk.entropy / 8) * 11;
        const pz = 5.5;
        curvePoints.push(new THREE.Vector3(px, py, pz));
      });

      const curve = new THREE.CatmullRomCurve3(curvePoints);
      const tubeGeo = new THREE.TubeGeometry(curve, 64, 0.22, 8, false);
      const tubeMat = new THREE.MeshStandardMaterial({
        color: 0x38bdf8,
        emissive: 0x0284c7,
        emissiveIntensity: 0.4,
        roughness: 0.1,
      });
      const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
      mainGroup.add(tubeMesh);
    }

    // Animation loop
    let animationId: number;
    const animate = () => {
      animationId = requestAnimationFrame(animate);
      if (autoRotate) {
        mainGroup.rotation.y += 0.005;
      }
      renderer.render(scene, camera);
    };
    animate();

    // Mouse interactive raycasting for section hover
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handleMouseMove = (event: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(mainGroup.children);
      const hit = intersects.find(i => i.object.userData?.section);
      if (hit) {
        setHoveredSection(`${hit.object.userData.section} (${hit.object.userData.address}) · Entropy: ${hit.object.userData.entropy.toFixed(2)}/8.0`);
      } else {
        setHoveredSection(null);
      }
    };

    renderer.domElement.addEventListener('mousemove', handleMouseMove);

    // Resize handler
    const handleResize = () => {
      if (!container) return;
      const newW = container.clientWidth;
      const newH = container.clientHeight || 340;
      camera.aspect = newW / newH;
      camera.updateProjectionMatrix();
      renderer.setSize(newW, newH);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', handleResize);
      renderer.domElement.removeEventListener('mousemove', handleMouseMove);
      renderer.dispose();
      materialsRef.current.forEach(m => m.dispose());
    };
  }, [sections, entropyChunks, autoRotate, wireframe]);

  return (
    <div className="relative w-full rounded-xl border border-neutral-800 bg-neutral-950/80 overflow-hidden shadow-2xl">
      {/* 3D Viewport Controls & Overlay Bar */}
      <div className="absolute top-3 left-3 right-3 z-10 flex items-center justify-between pointer-events-none">
        <div className="flex items-center gap-2 pointer-events-auto bg-neutral-900/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-neutral-800 text-xs">
          <Layers className="w-3.5 h-3.5 text-indigo-400" />
          <span className="font-semibold text-neutral-200">Binary Memory Map & Entropy</span>
          <span className="text-neutral-500 font-mono text-[11px]">{fileName}</span>
        </div>

        <div className="flex items-center gap-1.5 pointer-events-auto bg-neutral-900/90 backdrop-blur-md p-1 rounded-lg border border-neutral-800">
          <button
            onClick={() => setAutoRotate(!autoRotate)}
            className={`p-1.5 rounded-md text-xs transition-colors ${
              autoRotate ? 'bg-indigo-600/30 text-indigo-300' : 'text-neutral-400 hover:text-neutral-200'
            }`}
            title="Toggle Auto Rotation"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setWireframe(!wireframe)}
            className={`p-1.5 rounded-md text-xs transition-colors ${
              wireframe ? 'bg-indigo-600/30 text-indigo-300' : 'text-neutral-400 hover:text-neutral-200'
            }`}
            title="Toggle Wireframe Mesh"
          >
            <Eye className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Hover Information Banner */}
      {hoveredSection && (
        <div className="absolute bottom-3 left-3 z-10 bg-neutral-900/95 backdrop-blur-md border border-neutral-700/60 px-3 py-1.5 rounded-lg text-xs font-mono text-cyan-300 shadow-lg pointer-events-none animate-fadeIn">
          {hoveredSection}
        </div>
      )}

      {/* Legend Footer */}
      <div className="absolute bottom-3 right-3 z-10 flex items-center gap-3 bg-neutral-900/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-neutral-800 text-[11px] text-neutral-400 pointer-events-none">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-indigo-500"></span>
          <span>Executable .text</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500"></span>
          <span>Data .data</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-red-500"></span>
          <span>Packed / High Entropy (&gt;7.0)</span>
        </div>
      </div>

      {/* Three.js Canvas Container */}
      <div ref={mountRef} className="w-full h-80 cursor-grab active:cursor-grabbing" />
    </div>
  );
};
