export function createSceneAtmosphere(THREE, scene) {
  const group = new THREE.Group();
  const geometries = new Set();
  const materials = new Set();
  const rings = [];
  const nodes = [];
  const packets = [];
  scene.add(group);

  const trackGeometry = (geometry) => {
    geometries.add(geometry);
    return geometry;
  };

  const trackMaterial = (material) => {
    materials.add(material);
    return material;
  };

  const gridPoints = [];
  for (let x = -3.5; x <= 3.5; x += 0.5) {
    gridPoints.push(new THREE.Vector3(x, -2.1, -2.6), new THREE.Vector3(x, 2.1, -2.6));
  }
  for (let y = -2; y <= 2; y += 0.5) {
    gridPoints.push(new THREE.Vector3(-3.5, y, -2.6), new THREE.Vector3(3.5, y, -2.6));
  }

  const gridGeometry = trackGeometry(new THREE.BufferGeometry().setFromPoints(gridPoints));
  const gridMaterial = trackMaterial(new THREE.LineBasicMaterial({
    color: '#236080',
    transparent: true,
    opacity: 0.16,
    depthWrite: false
  }));
  group.add(new THREE.LineSegments(gridGeometry, gridMaterial));

  const ringMaterial = trackMaterial(new THREE.MeshBasicMaterial({
    color: '#318bb4',
    transparent: true,
    opacity: 0.32,
    depthWrite: false
  }));
  const violetRingMaterial = trackMaterial(new THREE.MeshBasicMaterial({
    color: '#8b79db',
    transparent: true,
    opacity: 0.26,
    depthWrite: false
  }));

  [
    {radius: 1.54, z: -0.62, rotation: [0.72, 0.08, 0.12], material: ringMaterial},
    {radius: 1.82, z: -0.9, rotation: [1.12, 0.14, -0.24], material: violetRingMaterial},
    {radius: 2.08, z: -1.15, rotation: [0.2, 0.68, 0.32], material: ringMaterial}
  ].forEach(({radius, z, rotation, material}, index) => {
    const geometry = trackGeometry(new THREE.TorusGeometry(radius, index === 1 ? 0.012 : 0.009, 6, 88));
    const ring = new THREE.Mesh(geometry, material);
    ring.position.z = z;
    ring.rotation.set(...rotation);
    group.add(ring);
    rings.push(ring);
  });

  const particleCount = 42;
  const basePositions = new Float32Array(particleCount * 3);
  for (let index = 0; index < particleCount; index += 1) {
    basePositions[index * 3] = ((index * 37) % 101) / 16 - 3.15;
    basePositions[index * 3 + 1] = ((index * 61) % 97) / 25 - 1.92;
    basePositions[index * 3 + 2] = -1.8 + ((index * 17) % 19) / 12;
  }

  const particleGeometry = trackGeometry(new THREE.BufferGeometry());
  const particleAttribute = new THREE.BufferAttribute(basePositions.slice(), 3);
  particleGeometry.setAttribute('position', particleAttribute);
  const particleMaterial = trackMaterial(new THREE.PointsMaterial({
    color: '#87dcff',
    size: 0.035,
    transparent: true,
    opacity: 0.62,
    sizeAttenuation: true,
    depthWrite: false
  }));
  group.add(new THREE.Points(particleGeometry, particleMaterial));

  const nodeGeometry = trackGeometry(new THREE.SphereGeometry(0.045, 8, 8));
  const nodeMaterial = trackMaterial(new THREE.MeshBasicMaterial({
    color: '#55cfff',
    transparent: true,
    opacity: 0.72,
    depthWrite: false
  }));
  const networkPositions = [];
  for (let index = 0; index < 16; index += 1) {
    const angle = (index / 16) * Math.PI * 2;
    const position = [
      Math.cos(angle) * (2.05 + (index % 3) * 0.12),
      Math.sin(angle) * (1.35 + (index % 2) * 0.12),
      index % 2 ? -0.18 : -0.82
    ];
    networkPositions.push(position);
    const node = new THREE.Mesh(nodeGeometry, nodeMaterial);
    node.position.set(...position);
    group.add(node);
    nodes.push(node);
  }

  const networkPoints = [];
  networkPositions.forEach((position, index) => {
    const next = networkPositions[(index + 1) % networkPositions.length];
    networkPoints.push(new THREE.Vector3(...position), new THREE.Vector3(...next));
    if (index % 2 === 0) {
      networkPoints.push(new THREE.Vector3(...position), new THREE.Vector3(0, 0, -0.65));
    }
  });
  const networkGeometry = trackGeometry(new THREE.BufferGeometry().setFromPoints(networkPoints));
  const networkMaterial = trackMaterial(new THREE.LineBasicMaterial({
    color: '#338db8',
    transparent: true,
    opacity: 0.2,
    depthWrite: false
  }));
  group.add(new THREE.LineSegments(networkGeometry, networkMaterial));

  const packetGeometry = trackGeometry(new THREE.SphereGeometry(0.027, 7, 7));
  const packetMaterials = ['#51d7ff', '#a58bff', '#54ddbb'].map((color) =>
    trackMaterial(new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.9,
      depthWrite: false
    }))
  );

  for (let index = 0; index < 9; index += 1) {
    const packet = new THREE.Mesh(packetGeometry, packetMaterials[index % packetMaterials.length]);
    group.add(packet);
    packets.push(packet);
  }

  return {
    update(time, delta, reducedMotion) {
      const motion = reducedMotion ? 0 : 1;
      rings[0].rotation.z += delta * 0.035 * motion;
      rings[1].rotation.x -= delta * 0.025 * motion;
      rings[2].rotation.y += delta * 0.02 * motion;

      const positions = particleAttribute.array;
      for (let index = 0; index < particleCount; index += 1) {
        positions[index * 3 + 1] = basePositions[index * 3 + 1]
          + Math.sin(time * 0.42 + index * 0.8) * 0.045 * motion;
      }
      particleAttribute.needsUpdate = true;

      nodes.forEach((node, index) => {
        const pulse = 0.86 + (Math.sin(time * 1.4 + index * 0.6) + 1) * 0.12 * motion;
        node.scale.setScalar(pulse);
      });

      packets.forEach((packet, index) => {
        const progress = (time * 0.085 + index / packets.length) % 1;
        packet.position.set(
          -3.15 + progress * 6.3,
          Math.sin(progress * Math.PI * 2 + index) * 0.72,
          -0.35 + Math.cos(progress * Math.PI * 2 + index) * 0.6
        );
      });
    },
    dispose() {
      scene.remove(group);
      geometries.forEach((geometry) => geometry.dispose());
      materials.forEach((material) => material.dispose());
    }
  };
}