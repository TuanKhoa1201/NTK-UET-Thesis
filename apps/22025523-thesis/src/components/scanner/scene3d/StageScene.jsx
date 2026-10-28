import {useMemo, useRef} from 'react';
import {useFrame} from '@react-three/fiber';

const cyan = '#48d7ff';
const violet = '#9e86ff';
const amber = '#ffbd5c';
const red = '#ff6474';
const green = '#46dfaa';

const layouts = [
  [[-2, 0, 0], [-1.4, 0.7, 0], [-1.4, -0.7, 0]],
  [[-2, 1, 0], [-1, 0.4, 0], [-1, -0.4, 0], [0, 0.8, 0], [0, 0, 0], [0, -0.8, 0]],
  [[-1.8, 1, 0], [-1.8, 0, 0], [-1.8, -1, 0], [-0.7, 1, 0], [-0.7, 0, 0], [-0.7, -1, 0]],
  [[-1.8, 0, 0], [-0.8, 0.7, 0], [-0.8, -0.7, 0], [0.3, 0.5, 0], [0.3, -0.5, 0]],
  [[-1.8, 1, 0], [-0.8, 0.4, 0], [-0.8, -0.4, 0], [0.2, 0.8, 0], [0.2, 0, 0], [0.2, -0.8, 0]],
  [[-1.8, 1, 0], [-1.8, 0, 0], [-1.8, -1, 0], [-0.6, 0.7, 0], [-0.6, 0, 0], [-0.6, -0.7, 0], [0.6, 0.7, 0], [0.6, 0, 0], [0.6, -0.7, 0], [1.8, 0.5, 0], [1.8, -0.5, 0]],
  [[-2, 1, 0], [-2, 0, 0], [-2, -1, 0], [0, 0, 0], [2, 0, 0]],
  [[-1.4, 0, 0], [-0.9, 0.8, 0], [-0.3, 1.1, 0], [0.4, 1.1, 0], [1, 0.8, 0], [1.4, 0, 0], [1, -0.8, 0], [0.4, -1.1, 0], [-0.3, -1.1, 0]],
  [[-1.8, 0, 0], [-0.5, 0, 0], [1.1, 0.8, 0], [1.1, 0, 0], [1.1, -0.8, 0]],
  [[-1.7, -0.8, 0], [-1.1, -0.8, 0], [-0.5, -0.8, 0], [0.1, -0.8, 0], [0.7, -0.8, 0], [1.5, 0.5, 0]]
];

function Link({from, to, color}) {
  const dx = to[0] - from[0];
  const dy = to[1] - from[1];

  return (
    <mesh
      position={[(from[0] + to[0]) / 2, (from[1] + to[1]) / 2, -0.08]}
      rotation={[0, 0, Math.atan2(dy, dx)]}
    >
      <boxGeometry args={[Math.hypot(dx, dy), 0.018, 0.018]} />
      <meshBasicMaterial color={color} transparent opacity={0.42} />
    </mesh>
  );
}

function Core() {
  const group = useRef();
  const ring = useRef();
  useFrame((state, delta) => {
    if (!group.current || !ring.current) return;
    group.current.rotation.y += delta * 0.22;
    ring.current.rotation.z -= delta * 0.28;
    const pulse = 1 + Math.sin(state.clock.elapsedTime * 2.2) * 0.035;
    group.current.scale.setScalar(pulse);
  });

  return (
    <group>
      <group ref={group}>
        <mesh>
          <icosahedronGeometry args={[0.52, 1]} />
          <meshBasicMaterial color={cyan} wireframe />
        </mesh>
        <mesh>
          <sphereGeometry args={[0.25, 16, 16]} />
          <meshBasicMaterial color="#63cfff" transparent opacity={0.78} />
        </mesh>
      </group>
      <mesh ref={ring} rotation={[0.8, 0.2, 0]}>
        <torusGeometry args={[0.88, 0.014, 6, 48]} />
        <meshBasicMaterial color={violet} />
      </mesh>
      <mesh rotation={[1.2, 0, 0]}>
        <torusGeometry args={[1.12, 0.01, 6, 48]} />
        <meshBasicMaterial color={cyan} transparent opacity={0.7} />
      </mesh>
    </group>
  );
}

function StageNodes({phase}) {
  const group = useRef();
  const nodes = layouts[phase] || layouts[0];
  const color = phase === 5 ? violet : phase === 8 ? amber : phase === 2 ? red : cyan;

  useFrame((state) => {
    if (!group.current) return;
    group.current.position.y = Math.sin(state.clock.elapsedTime * 0.65) * 0.035;
  });

  return (
    <group ref={group}>
      {nodes.slice(0, -1).map((node, index) => (
        <Link key={`link-${index}`} from={node} to={nodes[index + 1]} color={phase === 6 ? [cyan, violet, '#ffffff'][index % 3] : color} />
      ))}
      {nodes.map((position, index) => (
        <mesh key={`node-${index}`} position={position}>
          {phase === 0 || phase === 9
            ? <boxGeometry args={[0.24, 0.24, 0.24]} />
            : <sphereGeometry args={[0.105, 10, 10]} />}
          <meshBasicMaterial color={phase === 8 && index > 1 ? [red, amber, green][(index - 2) % 3] : color} />
        </mesh>
      ))}
    </group>
  );
}

function DataPackets({phase}) {
  const refs = useRef([]);
  const color = phase === 5 ? violet : phase === 8 ? amber : cyan;
  const seeds = useMemo(() => Array.from({length: 12}, (_, index) => index / 12), []);

  useFrame((state) => {
    refs.current.forEach((mesh, index) => {
      if (!mesh) return;
      const progress = (state.clock.elapsedTime * 0.16 + seeds[index]) % 1;
      mesh.position.set(-2.3 + progress * 4.6, Math.sin(progress * Math.PI * 2 + index) * 0.22, 0.16);
    });
  });

  return (
    <group>
      {seeds.map((seed, index) => (
        <mesh key={seed} ref={(mesh) => { refs.current[index] = mesh; }}>
          <sphereGeometry args={[0.035, 6, 6]} />
          <meshBasicMaterial color={color} />
        </mesh>
      ))}
    </group>
  );
}

export default function StageScene({phase}) {
  const stage = Math.max(0, Math.min(9, Number.isInteger(phase) ? phase : 0));
  const cluster = useRef();

  useFrame((state, delta) => {
    if (cluster.current) cluster.current.rotation.y += delta * 0.045;
    state.camera.position.x = Math.sin(state.clock.elapsedTime * 0.12) * 0.14;
    state.camera.lookAt(0, 0, 0);
  });

  return (
    <group ref={cluster}>
      <Core />
      <StageNodes phase={stage} />
      <DataPackets phase={stage} />
      {stage === 2 && <ScannerPlane />}
      {stage === 7 && <ScoreRing />}
    </group>
  );
}

function ScannerPlane() {
  const plane = useRef();
  useFrame((state) => {
    if (plane.current) plane.current.position.y = Math.sin(state.clock.elapsedTime * 1.5) * 1.2;
  });

  return (
    <mesh ref={plane} position={[0, 0, 0.25]}>
      <planeGeometry args={[4.4, 0.035]} />
      <meshBasicMaterial color="#b3f3ff" transparent opacity={0.72} />
    </mesh>
  );
}

function ScoreRing() {
  const ring = useRef();
  useFrame((_, delta) => {
    if (ring.current) ring.current.rotation.z += delta * 0.22;
  });

  return (
    <mesh ref={ring} position={[0, 0, -0.2]}>
      <torusGeometry args={[1.55, 0.045, 6, 36, Math.PI * 1.55]} />
      <meshBasicMaterial color={green} />
    </mesh>
  );
}