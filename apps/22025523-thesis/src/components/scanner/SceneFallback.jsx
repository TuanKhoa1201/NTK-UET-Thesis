export default function SceneFallback({step, onRetry, loading = false}) {
  return (
    <div className="scene-recovery" role="status">
      <svg className="scene-recovery-diagram" viewBox="0 0 360 170" aria-hidden="true">
        <defs>
          <linearGradient id="scanner-fallback-link"><stop stopColor="#38bdf8" /><stop offset="1" stopColor="#a78bfa" /></linearGradient>
        </defs>
        <path d="M36 85 H150 M210 85 H324" stroke="url(#scanner-fallback-link)" strokeWidth="2" strokeDasharray="6 9" />
        <circle className="scene-recovery-node" cx="34" cy="85" r="13" fill="#123d56" stroke="#38bdf8" />
        <circle className="scene-recovery-node" cx="326" cy="85" r="13" fill="#2b214b" stroke="#a78bfa" />
        <circle className="scene-recovery-ring" cx="180" cy="85" r="48" fill="none" stroke="#38bdf8" strokeWidth="2" strokeDasharray="18 12" />
        <circle className="scene-recovery-ring scene-recovery-ring--inner" cx="180" cy="85" r="30" fill="none" stroke="#a78bfa" strokeWidth="2" strokeDasharray="9 8" />
        <circle cx="180" cy="85" r="15" fill="#1c5680" stroke="#8de6ff" />
        <circle className="scene-recovery-packet" r="5" fill="#8de6ff">
          <animateMotion dur="3s" repeatCount="indefinite" path="M36 85 H324" />
        </circle>
      </svg>
      <strong>{loading ? 'Đang chuẩn bị mô hình 3D…' : 'Mô phỏng trực quan đơn giản'}</strong>
      <p>{loading ? 'Các bước phân tích vẫn hiển thị trong khi mô hình được tải.' : 'Không thể khởi tạo mô hình 3D. Bạn vẫn có thể tiếp tục phân tích và theo dõi tiến trình ở chế độ trực quan đơn giản.'}</p>
      <small>BƯỚC HIỆN TẠI · {step?.title || 'Chờ phân tích'}</small>
      {!loading && onRetry && <button className="button-secondary" onClick={onRetry}>Tải lại mô hình 3D</button>}
    </div>
  );
}