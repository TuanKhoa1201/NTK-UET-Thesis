const palette = {
  cyan: '#48d7ff',
  blue: '#438cff',
  violet: '#a48bff',
  amber: '#ffbd5c',
  red: '#ff6474',
  green: '#46dfaa',
  white: '#eaf8ff',
  muted: '#24445d'
};

export function createScanScene(THREE, scene) {
  const geometries = new Set();
  const materials = new Set();
  const stages = [];
  const animators = [];
  const packets = [];
  const pulsingNodes = [];
  const motion = new THREE.Group();
  scene.add(motion);

  const material = (color, options = {}) => {
    const value = new THREE.MeshStandardMaterial({
      color,
      emissive: color,
      emissiveIntensity: options.emissive ?? 0.35,
      metalness: 0.25,
      roughness: 0.48,
      transparent: options.opacity !== undefined,
      opacity: options.opacity ?? 1,
      wireframe: options.wireframe ?? false
    });
    materials.add(value);
    return value;
  };

  const geometry = (value) => {
    geometries.add(value);
    return value;
  };

  const shapes = {
    cube: geometry(new THREE.BoxGeometry(0.34, 0.34, 0.34)),
    file: geometry(new THREE.BoxGeometry(0.2, 0.28, 0.045)),
    sphere: geometry(new THREE.SphereGeometry(0.085, 12, 10)),
    smallSphere: geometry(new THREE.SphereGeometry(0.043, 8, 8)),
    octahedron: geometry(new THREE.OctahedronGeometry(0.15, 0)),
    core: geometry(new THREE.IcosahedronGeometry(0.42, 1)),
    ring: geometry(new THREE.TorusGeometry(0.78, 0.018, 8, 72)),
    innerRing: geometry(new THREE.TorusGeometry(0.58, 0.012, 6, 64)),
    panel: geometry(new THREE.BoxGeometry(0.44, 0.34, 0.045)),
    bar: geometry(new THREE.BoxGeometry(0.18, 1, 0.16)),
    plane: geometry(new THREE.PlaneGeometry(5.4, 0.035))
  };

  const mats = {
    cyan: material(palette.cyan),
    blue: material(palette.blue),
    violet: material(palette.violet),
    amber: material(palette.amber),
    red: material(palette.red),
    green: material(palette.green),
    white: material(palette.white),
    muted: material(palette.muted, {emissive: 0.08}),
    glass: material(palette.blue, {opacity: 0.28, emissive: 0.12})
  };

  const addMesh = (group, shape, mat, position, scale) => {
    const mesh = new THREE.Mesh(shape, mat);
    mesh.position.set(...position);
    if (scale) mesh.scale.set(...scale);
    group.add(mesh);
    pulsingNodes.push(mesh);
    return mesh;
  };

  const addLine = (group, from, to, mat, opacity = 0.55) => {
    const points = [
      new THREE.Vector3(...from),
      new THREE.Vector3(...to)
    ];
    const lineGeometry = geometry(new THREE.BufferGeometry().setFromPoints(points));
    const lineMaterial = material(mat.color, {opacity, emissive: 0.12});
    lineMaterial.transparent = true;
    const line = new THREE.Line(
      lineGeometry,
      lineMaterial
    );
    group.add(line);
    return line;
  };

  const addPacket = (group, path, mat, offset = 0, speed = 0.22) => {
    const mesh = new THREE.Mesh(shapes.smallSphere, mat);
    group.add(mesh);
    packets.push({mesh, path, offset, speed});
  };

  const addGraph = (group, points, edges, color = mats.cyan) => {
    edges.forEach(([from, to]) => addLine(group, points[from], points[to], color));
    points.forEach((point, index) => {
      addMesh(group, index % 3 === 0 ? shapes.octahedron : shapes.sphere, color, point);
    });
  };

  for (let index = 0; index < 10; index += 1) {
    const stage = new THREE.Group();
    stage.visible = index === 0;
    motion.add(stage);
    stages.push(stage);
  }

  const intake = stages[0];
  const repository = addMesh(intake, shapes.cube, mats.cyan, [-2.55, 0, 0], [1.55, 1.55, 1.55]);
  repository.material = material(palette.cyan, {wireframe: true});
  animators.push((time, delta) => {
    repository.position.x = -2.35 + Math.sin(time * 0.55) * 0.28;
    repository.rotation.y += delta * 0.3;
    repository.rotation.x += delta * 0.12;
  });
  for (let index = 0; index < 6; index += 1) {
    const angle = (index / 6) * Math.PI * 2;
    addMesh(intake, shapes.file, index % 2 ? mats.violet : mats.cyan, [
      -1.35 + Math.cos(angle) * 0.48,
      Math.sin(angle) * 0.62,
      0.1
    ]);
    addPacket(intake, [[-1.3, Math.sin(angle) * 0.5, 0.1], [0.45, 0, 0]], mats.cyan, index / 6);
  }

  const tree = [
    [-2.25, 1.3, 0], [-1.2, 0.68, 0], [-1.2, -0.05, 0],
    [-1.2, -0.78, 0], [-0.1, 1.02, 0], [-0.1, 0.35, 0],
    [-0.1, -0.35, 0], [-0.1, -1.02, 0], [1.05, 0.65, 0],
    [1.05, -0.45, 0], [2.15, 0.2, 0]
  ];
  addGraph(stages[1], tree, [[0, 1], [0, 2], [0, 3], [1, 4], [1, 5], [2, 6], [3, 7], [4, 8], [7, 9], [8, 10]], mats.cyan);
  tree.slice(1, 7).forEach((point, index) => addPacket(stages[1], [tree[0], point], mats.blue, index / 6));

  const grep = stages[2];
  for (let row = -1; row <= 1; row += 1) {
    for (let column = 0; column < 4; column += 1) {
      addMesh(grep, shapes.panel, column === 2 && row === 0 ? mats.amber : mats.blue, [
        -2.05 + column * 0.78,
        row * 0.72,
        0
      ]);
    }
  }
  const scanPlane = new THREE.Mesh(geometry(new THREE.PlaneGeometry(0.05, 2.5)), mats.white);
  scanPlane.position.set(-2.3, 0, 0.14);
  grep.add(scanPlane);
  animators.push((time) => {
    scanPlane.position.x = -2.3 + ((time * 0.65) % 1) * 4.7;
  });
  addMesh(grep, shapes.octahedron, mats.red, [0.28, 0, 0.18]);

  const context = stages[3];
  addMesh(context, shapes.octahedron, mats.violet, [0.2, 0, 0.2], [1.4, 1.4, 1.4]);
  [[-1.25, 0.72, 0], [-1.25, -0.72, 0], [1.55, 0.72, 0], [1.55, -0.72, 0], [0.2, 1.35, 0], [0.2, -1.35, 0]]
    .forEach((point, index, all) => {
      addMesh(context, shapes.panel, index % 2 ? mats.cyan : mats.amber, point);
      addLine(context, [0.2, 0, 0], point, mats.blue, 0.45);
      addPacket(context, [[-1.25, 0.72, 0], point], mats.cyan, index / all.length);
    });

  const astPoints = [[0, 1.42, 0], [-1.2, 0.62, 0], [1.2, 0.62, 0], [-1.75, -0.35, 0], [-0.58, -0.35, 0], [0.58, -0.35, 0], [1.75, -0.35, 0], [-0.58, -1.25, 0], [0.58, -1.25, 0]];
  const astEdges = [[0, 1], [0, 2], [1, 3], [1, 4], [2, 5], [2, 6], [4, 7], [5, 8]];
  addGraph(stages[4], astPoints, astEdges, mats.violet);
  [[0, 2], [2, 5], [5, 8]].forEach(([from, to], index) => {
    addLine(stages[4], astPoints[from], astPoints[to], mats.green, 0.9);
    addPacket(stages[4], [astPoints[from], astPoints[to]], mats.green, index / 3, 0.35);
  });

  const neural = stages[5];
  const layers = [-2.25, -0.75, 0.75, 2.25];
  const rows = [-1.05, -0.35, 0.35, 1.05];
  layers.forEach((x, layer) => {
    rows.forEach((y, row) => {
      addMesh(neural, shapes.sphere, layer === 2 ? mats.violet : mats.blue, [x, y, 0]);
      if (layer < layers.length - 1) {
        rows.forEach((targetY, targetRow) => {
          if (targetRow % 2 === row % 2) {
            addLine(neural, [x, y, 0], [layers[layer + 1], targetY, 0], mats.violet, 0.22);
            if (row === targetRow) {
              addPacket(neural, [[x, y, 0], [layers[layer + 1], targetY, 0]], mats.cyan, (layer + row) / 7, 0.28);
            }
          }
        });
      }
    });
  });

  const fusion = stages[6];
  const sourcePoints = [[-2.5, 1.18, 0], [-2.5, 0, 0], [-2.5, -1.18, 0]];
  const sourceMats = [mats.cyan, mats.violet, mats.blue];
  sourcePoints.forEach((point, index) => {
    addMesh(fusion, shapes.octahedron, sourceMats[index], point);
    addLine(fusion, point, [0, 0, 0], sourceMats[index], 0.48);
    addPacket(fusion, [point, [0, 0, 0]], sourceMats[index], index / 3, 0.3);
  });
  addMesh(fusion, shapes.core, mats.white, [0, 0, 0], [0.7, 0.7, 0.7]);
  addLine(fusion, [0, 0, 0], [2.45, 0, 0], mats.cyan, 0.75);
  addPacket(fusion, [[0, 0, 0], [2.45, 0, 0]], mats.white, 0.35, 0.3);

  const scoring = stages[7];
  const gauge = new THREE.Mesh(
    geometry(new THREE.TorusGeometry(1.2, 0.075, 8, 48, Math.PI * 1.65)),
    mats.green
  );
  gauge.rotation.z = Math.PI * 0.68;
  scoring.add(gauge);
  for (let index = 0; index < 8; index += 1) {
    const angle = Math.PI * 0.84 + (index / 7) * Math.PI * 1.32;
    addMesh(scoring, shapes.smallSphere, index < 3 ? mats.green : mats.muted, [
      Math.cos(angle) * 1.2,
      Math.sin(angle) * 1.2,
      0.12
    ]);
  }
  addPacket(scoring, [[-2.3, 0, 0], [0, 0, 0]], mats.cyan, 0, 0.22);

  const triage = stages[8];
  const triageEnds = [[2.1, 1.05, 0], [2.1, 0, 0], [2.1, -1.05, 0]];
  const triageMats = [mats.red, mats.amber, mats.green];
  triageEnds.forEach((point, index) => {
    addLine(triage, [-1.45, 0, 0], point, triageMats[index], 0.65);
    addMesh(triage, shapes.cube, triageMats[index], point, [0.75, 0.75, 0.75]);
    addPacket(triage, [[-1.45, 0, 0], point], triageMats[index], index / 3, 0.27);
  });
  addMesh(triage, shapes.octahedron, mats.white, [-1.45, 0, 0]);

  const report = stages[9];
  addMesh(report, shapes.panel, mats.glass, [1.45, 0.1, 0], [2.6, 4.4, 1]);
  for (let index = 0; index < 5; index += 1) {
    const bar = addMesh(report, shapes.bar, [mats.red, mats.amber, mats.green, mats.cyan, mats.violet][index], [
      -2.1 + index * 0.43,
      -0.48,
      0.18
    ], [1, 0.42 + (index % 3) * 0.25, 1]);
    bar.position.y = -1.1 + bar.scale.y * 0.5;
  }
  for (let index = 0; index < 3; index += 1) {
    addMesh(report, shapes.panel, mats.cyan, [1.45, 0.8 - index * 0.38, 0.18], [1.5, 0.18, 0.7]);
  }
  addPacket(report, [[-2, 0, 0], [1.2, 0, 0]], mats.white, 0, 0.2);

  const core = new THREE.Group();
  const coreMesh = new THREE.Mesh(shapes.core, mats.cyan);
  core.add(coreMesh);
  const outerRing = new THREE.Mesh(shapes.ring, mats.violet);
  const innerRing = new THREE.Mesh(shapes.innerRing, mats.cyan);
  outerRing.rotation.x = 0.9;
  innerRing.rotation.y = 0.9;
  core.add(outerRing, innerRing);
  motion.add(core);

  return {
    update(time, delta, phase, reducedMotion) {
      const safePhase = Math.max(0, Math.min(9, Number.isInteger(phase) ? phase : 0));
      stages.forEach((stage, index) => {
        stage.visible = index === safePhase;
      });
      const speed = reducedMotion ? 0 : 1;
      core.rotation.y += delta * 0.2 * speed;
      core.rotation.x = Math.sin(time * 0.3) * 0.08 * speed;
      outerRing.rotation.z -= delta * 0.25 * speed;
      innerRing.rotation.x += delta * 0.18 * speed;
      stages[safePhase].rotation.y = Math.sin(time * 0.22) * 0.035 * speed;

      animators.forEach((animate) => animate(time * speed, delta * speed));
      packets.forEach(({mesh, path, offset, speed: packetSpeed}) => {
        const progress = (time * speed * packetSpeed + offset) % 1;
        const segment = Math.min(path.length - 2, Math.floor(progress * (path.length - 1)));
        const local = progress * (path.length - 1) - segment;
        const from = path[segment];
        const to = path[segment + 1];
        mesh.position.set(
          from[0] + (to[0] - from[0]) * local,
          from[1] + (to[1] - from[1]) * local,
          from[2] + (to[2] - from[2]) * local
        );
      });
      pulsingNodes.forEach((node, index) => {
        const pulse = reducedMotion ? 1 : 1 + Math.sin(time * 2 + index * 0.7) * 0.055;
        node.scale.multiplyScalar(pulse / (node.userData.lastPulse || 1));
        node.userData.lastPulse = pulse;
      });
    },
    dispose() {
      scene.remove(motion);
      geometries.forEach((value) => value.dispose());
      materials.forEach((value) => value.dispose());
    }
  };
}