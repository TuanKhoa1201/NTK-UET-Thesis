import {useCallback, useState} from 'react';
import ErrorBoundary from '../common/ErrorBoundary';
import SceneFallback from './SceneFallback';
import Scene3D from './scene3d/Scene3D';

const stageLabels = [
  ['Repo / ZIP Input', 'Intake Buffer', 'Source Stream'],
  ['Java Files', 'Package Graph', 'Source Inventory'],
  ['OpenGrep Rules', 'Pattern Scan', 'Candidate Signals'],
  ['Method Context', 'Code Slices', 'Context Window'],
  ['IRIS', 'Java AST', 'Source → Sink'],
  ['Qwen LoRA', 'API Role', 'Model Inference'],
  ['OpenGrep + IRIS + Qwen', 'Evidence Fusion', 'Combined Context'],
  ['SAST Scoring', 'Policy Adjustment', 'Threshold Check'],
  ['Alert Verification', 'REPORT / REVIEW', 'SUPPRESS'],
  ['Findings Summary', 'Metrics', 'Final Report']
];

export default function ScanStageVisual({step, index, previous, next, live = false, liveCounts = null}) {
  const [attempt, setAttempt] = useState(0);
  const [contextLost, setContextLost] = useState(false);
  const activeIndex = Math.max(0, Math.min(9, index));
  const retry = useCallback(() => {
    setContextLost(false);
    setAttempt((value) => value + 1);
  }, []);
  const handleFailure = useCallback(() => setContextLost(true), []);
  const empty = liveCounts && liveCounts.total === 0;
  const labels = empty
    ? ['0 ứng viên', 'Không có finding trong phạm vi hiện tại']
    : liveCounts
      ? [`REPORT ${liveCounts.report}`, `REVIEW ${liveCounts.review}`, `SUPPRESS ${liveCounts.suppress}`]
      : stageLabels[activeIndex];

  return (
    <div className="guided-visual visual-3d">
      {contextLost ? (
        <SceneFallback step={step} onRetry={retry} />
      ) : (
        <ErrorBoundary
          key={attempt}
          fallback={() => <SceneFallback step={step} onRetry={retry} />}
        >
          <Scene3D phase={activeIndex} onFailure={handleFailure} />
        </ErrorBoundary>
      )}
      <div className="scene3d-overlay" aria-label="Chú thích cảnh 3D">
        <span className="scene3d-mode"><i /> {liveCounts ? '3D · KẾT QUẢ THỰC TỪ BACKEND' : live ? '3D PIPELINE · TRỰC QUAN HÓA KHÁI NIỆM' : '3D PIPELINE'}</span>
        <span className="scene3d-counter">
          {String(activeIndex + 1).padStart(2, '0')} <i>/</i> 10
        </span>
        <div className="scene3d-callouts" key={`${activeIndex}-${liveCounts ? 'r' : 's'}`}>
          {labels.map((label, itemIndex) => (
            <span className={`scene3d-callout callout-${itemIndex}`} key={label}>
              <i />{label}
            </span>
          ))}
        </div>
      </div>
      <div className="scene3d-bar">
        <span>{previous ? `← ${previous.title}` : 'Bắt đầu pipeline'}</span>
        <b>BƯỚC {String(activeIndex + 1).padStart(2, '0')} · {step.title}</b>
        <span>{next ? `${next.title} →` : 'Kết quả phiên'}</span>
      </div>
    </div>
  );
}