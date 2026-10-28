import {useRef} from 'react';
import {useFrame} from '@react-three/fiber';
import * as THREE from 'three';

const CY = '#38bdf8';
const VI = '#a78bfa';
const BL = '#3b82f6';
const RED = '#ef6668';
const AM = '#f5b94c';
const GR = '#34c982';

function Grow({children}) {
  const ref = useRef();
  useFrame((_, delta) => {
    const k = THREE.MathUtils.lerp(ref.current.scale.x, 1, Math.min(1, delta * 4));
    ref.current.scale.setScalar(k);
  });
  return <group ref={ref} scale={0.01}>{children}</group>;
}

function Lines({pts, color = CY, opacity = 0.5}) {
  const arr = new Float32Array(pts.flat());
  return (
    <lineSegments>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[arr, 3]} />
      </bufferGeometry>
      <lineBasicMaterial color={color} transparent opacity={opacity} />
    </lineSegments>
  );
}

function Dot({color = CY, size = 0.08}) {
  return (
    <mesh>
      <sphereGeometry args={[size, 12, 12]} />
      <meshBasicMaterial color={color} />
    </mesh>
  );
}

function Travel({from, to, color = CY, speed = 0.3, offset = 0, size = 0.08}) {
  const ref = useRef();
  useFrame((state) => {
    const k = (state.clock.elapsedTime * speed + offset) % 1;
    ref.current.position.set(
      from[0] + (to[0] - from[0]) * k,
      from[1] + (to[1] - from[1]) * k,
      from[2] + (to[2] - from[2]) * k
    );
    ref.current.scale.setScalar(Math.sin(k * Math.PI) + 0.2);
  });
  return <group ref={ref}><Dot color={color} size={size} /></group>;
}

function Panel({position, size = [0.9, 0.55], color = CY, opacity = 0.18}) {
  return (
    <group position={position}>
      <mesh>
        <planeGeometry args={size} />
        <meshBasicMaterial color={color} transparent opacity={opacity} side={THREE.DoubleSide} />
      </mesh>
      <lineSegments>
        <edgesGeometry args={[new THREE.PlaneGeometry(size[0], size[1])]} />
        <lineBasicMaterial color={color} />
      </lineSegments>
    </group>
  );
}

function Spin({children, speed = 0.4, axis = 'y', position}) {
  const ref = useRef();
  useFrame((_, delta) => {
    ref.current.rotation[axis] += delta * speed;
  });
  return <group ref={ref} position={position}>{children}</group>;
}

/* 01 */
function Intake() {
  const pkg = useRef();
  useFrame((state) => {
    const k = (state.clock.elapsedTime * 0.35) % 1;
    pkg.current.position.x = -3.4 + k * 1.9;
    pkg.current.rotation.y += 0.02;
  });
  const files = Array.from({length: 6}, (_, i) => i);
  return (
    <Grow>
      <group ref={pkg}>
        <mesh>
          <boxGeometry args={[0.8, 0.8, 0.8]} />
          <meshBasicMaterial color={CY} wireframe />
        </mesh>
      </group>
      <Spin speed={0.5}>
        {files.map((i) => (
          <mesh key={i} position={[Math.cos(i * 1.047) * 2, Math.sin(i * 1.047) * 0.3, Math.sin(i * 1.047) * 2]}>
            <boxGeometry args={[0.22, 0.3, 0.05]} />
            <meshBasicMaterial color={i % 2 ? VI : CY} />
          </mesh>
        ))}
      </Spin>
    </Grow>
  );
}

/* 02 */
function Inventory() {
  const panels = [];
  for (let r = 0; r < 3; r += 1) for (let c = 0; c < 4; c += 1) panels.push([-3 + c * 0.55, 1.2 - r * 0.7, -0.5]);
  const lines = panels.map((p) => [p[0], p[1], p[2], p[0], 0, -0.5]);
  return (
    <Grow>
      <group position={[-0.4, 0, 0]}>
        {panels.map((p, i) => <Panel key={i} position={p} size={[0.4, 0.5]} color={i % 3 ? CY : VI} />)}
        <Lines pts={lines.map((l) => [[l[0], l[1], l[2]], [l[3], l[4], l[5]]]).flat()} opacity={0.3} />
        {panels.slice(0, 6).map((p, i) => <Travel key={i} from={p} to={[p[0], 0, -0.5]} offset={i / 6} color={CY} size={0.05} />)}
      </group>
    </Grow>
  );
}

/* 03 */
function OpenGrep() {
  const plane = useRef();
  useFrame((state) => {
    plane.current.position.y = Math.sin(state.clock.elapsedTime * 1.2) * 1.3;
  });
  const marks = [[-2.7, 0.8, AM], [-2.0, -0.2, RED], [-2.5, -0.9, AM]];
  return (
    <Grow>
      <group position={[0, 0, 0]}>
        {[1, 0, -1].map((y, i) => <Panel key={i} position={[-2.4, y * 0.85, 0]} size={[1.6, 0.6]} color={BL} />)}
        <mesh ref={plane} position={[-2.4, 0, 0.05]}>
          <planeGeometry args={[1.9, 0.06]} />
          <meshBasicMaterial color="#9be8ff" transparent opacity={0.9} />
        </mesh>
        {marks.map((m, i) => (
          <group key={i}>
            <mesh position={[m[0], m[1], 0.1]}>
              <octahedronGeometry args={[0.1]} />
              <meshBasicMaterial color={m[2]} />
            </mesh>
            <Travel from={[m[0], m[1], 0.1]} to={[0, 0, 0]} color={m[2]} offset={i / 3} speed={0.25} size={0.06} />
          </group>
        ))}
      </group>
    </Grow>
  );
}

/* 04 */
function Context() {
  const around = [[-0.9, 0.7], [0.9, 0.7], [-1, -0.7], [1, -0.7], [0, 1.25]];
  return (
    <Grow>
      <group position={[2.4, 0, 0]}>
        <Panel position={[0, 0, 0.2]} size={[1.3, 0.8]} color={AM} opacity={0.3} />
        {around.map((a, i) => <Panel key={i} position={[a[0] * 1.15, a[1], -0.2]} size={[0.7, 0.4]} color={CY} />)}
        <Lines pts={around.flatMap((a) => [[0, 0, 0.2], [a[0] * 1.15, a[1], -0.2]])} />
        <Spin speed={0.8}>
          <mesh position={[0, 0, 0.2]}>
            <octahedronGeometry args={[0.28]} />
            <meshBasicMaterial color={VI} wireframe />
          </mesh>
        </Spin>
      </group>
    </Grow>
  );
}

/* 05 */
function Ast() {
  const nodes = [[0, 1.5], [-1, 0.6], [1, 0.6], [-1.5, -0.3], [-0.5, -0.3], [0.5, -0.3], [1.5, -0.3], [-0.5, -1.2], [0.5, -1.2]];
  const edges = [[0, 1], [0, 2], [1, 3], [1, 4], [2, 5], [2, 6], [4, 7], [5, 8]];
  const p = (i) => [nodes[i][0], nodes[i][1], 0];
  const path = [[0, 2], [2, 5], [5, 8]];
  return (
    <Grow>
      <group position={[-2.5, 0, -0.5]}>
        <Spin speed={0.25}>
          <Lines pts={edges.flatMap(([a, b]) => [p(a), p(b)])} color={VI} opacity={0.6} />
          {nodes.map((n, i) => (
            <group key={i} position={[n[0], n[1], 0]}><Dot color={i % 3 ? VI : CY} size={0.09} /></group>
          ))}
          {path.map(([a, b], i) => <Travel key={i} from={p(a)} to={p(b)} color="#ffffff" offset={i / 3} speed={0.3} size={0.07} />)}
        </Spin>
      </group>
    </Grow>
  );
}

/* 06 */
function Network() {
  const layers = [-2.4, -0.8, 0.8, 2.4];
  const ys = [1.2, 0.4, -0.4, -1.2];
  const segs = [];
  for (let l = 0; l < 3; l += 1) for (const a of ys) for (const b of ys) segs.push([layers[l], a, 0], [layers[l + 1], b, 0]);
  return (
    <Grow>
      <group position={[0, 0, -1.6]}>
        <Lines pts={segs} color={BL} opacity={0.18} />
        {layers.map((x) => ys.map((y) => <group key={`${x}${y}`} position={[x, y, 0]}><Dot color={BL} size={0.07} /></group>))}
        {[0, 1, 2].map((l) => ys.map((y, i) => (
          <Travel key={`${l}${i}`} from={[layers[l], y, 0]} to={[layers[l + 1], ys[(i + 1) % 4], 0]} offset={(l + i / 4) / 3} speed={0.4} color="#9be8ff" size={0.06} />
        )))}
      </group>
    </Grow>
  );
}

/* 07 */
function Fusion() {
  const src = [[-3.2, 1.6, CY], [-3.2, 0, VI], [-3.2, -1.6, BL]];
  return (
    <Grow>
      {src.map((s, i) => (
        <group key={i}>
          <Lines pts={[[s[0], s[1], 0], [0, 0, 0]]} color={s[2]} opacity={0.3} />
          {[0, 0.33, 0.66].map((o) => <Travel key={o} from={[s[0], s[1], 0]} to={[0, 0, 0]} color={s[2]} offset={o + i * 0.1} speed={0.4} size={0.08} />)}
        </group>
      ))}
      <Travel from={[0, 0, 0]} to={[3.2, 0, 0]} color="#ffffff" speed={0.35} size={0.12} />
      <Lines pts={[[0, 0, 0], [3.2, 0, 0]]} color="#ffffff" opacity={0.4} />
    </Grow>
  );
}

/* 08 */
function Scoring() {
  const dots = useRef([]);
  useFrame((state) => {
    const progress = ((state.clock.elapsedTime * 0.25) % 1) * 0.85;
    dots.current.forEach((m, i) => {
      if (m) m.material.color.set(i / 24 <= progress ? '#6fe2b0' : '#27394d');
    });
  });
  return (
    <Grow>
      <Spin speed={0.15} axis="z" position={[2.4, 0, 0]}>
        {Array.from({length: 24}, (_, i) => (
          <mesh key={i} ref={(m) => { dots.current[i] = m; }} position={[Math.cos(i / 24 * Math.PI * 1.7 + 2.2) * 1.2, Math.sin(i / 24 * Math.PI * 1.7 + 2.2) * 1.2, 0]}>
            <sphereGeometry args={[0.08, 10, 10]} />
            <meshBasicMaterial color="#27394d" />
          </mesh>
        ))}
      </Spin>
      <Travel from={[0, 0, 0]} to={[2.4, 0, 0]} color={CY} speed={0.4} size={0.07} />
      <Travel from={[0, 0, 0]} to={[2.4, 0, 0]} color={VI} speed={0.4} offset={0.5} size={0.07} />
    </Grow>
  );
}

/* 09 */
function Triage() {
  const out = [[3, 1.5, RED], [3, 0, AM], [3, -1.5, GR]];
  return (
    <Grow>
      {out.map((o, i) => (
        <group key={i}>
          <Lines pts={[[0, 0, 0], [o[0], o[1], 0]]} color={o[2]} opacity={0.4} />
          {[0, 0.5].map((off) => <Travel key={off} from={[0, 0, 0]} to={[o[0], o[1], 0]} color={o[2]} offset={off + i * 0.17} speed={0.35} size={0.09} />)}
          <mesh position={[o[0], o[1], 0]}>
            <boxGeometry args={[0.35, 0.35, 0.35]} />
            <meshBasicMaterial color={o[2]} wireframe />
          </mesh>
        </group>
      ))}
    </Grow>
  );
}

/* 10 */
function Report() {
  const bars = [0.5, 0.9, 0.65, 1.2, 0.8];
  return (
    <Grow>
      <Spin speed={0.3} position={[2.4, 0, 0]}>
        <Panel position={[0, 0, 0]} size={[1.4, 1.9]} color="#ffffff" opacity={0.12} />
        {[0.6, 0.2, -0.2].map((y) => <Panel key={y} position={[0, y, 0.02]} size={[1, 0.08]} color={CY} opacity={0.6} />)}
      </Spin>
      {bars.map((h, i) => (
        <mesh key={i} position={[-3 + i * 0.4, -1.4 + h / 2, 0]}>
          <boxGeometry args={[0.22, h, 0.22]} />
          <meshBasicMaterial color={[RED, AM, GR, CY, VI][i]} transparent opacity={0.85} />
        </mesh>
      ))}
    </Grow>
  );
}

const scenes = [Intake, Inventory, OpenGrep, Context, Ast, Network, Fusion, Scoring, Triage, Report];

export const phaseColors = [CY, CY, BL, AM, VI, BL, '#ffffff', GR, RED, GR];

export default function PhaseObjects({phase}) {
  const Scene = scenes[phase] || Intake;
  return <Scene key={phase} />;
}