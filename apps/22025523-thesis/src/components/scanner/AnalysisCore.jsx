import {useState} from 'react';
import {motion} from 'framer-motion';
import {Icon} from '../common/Ui';

const modules=[
  {name:'OpenGrep',short:'STATIC',icon:'ScanSearch',description:'Tìm candidate theo quy tắc phân tích tĩnh.'},
  {name:'IRIS',short:'CONTEXT',icon:'GitBranch',description:'Bổ sung ngữ cảnh Java và bằng chứng dataflow.'},
  {name:'Qwen + LoRA',short:'ROLE INFERENCE',icon:'Cpu',description:'Phân loại vai trò API; không tự xác nhận lỗ hổng.'},
  {name:'Evidence Fusion',short:'FUSION',icon:'Share2',description:'Kết hợp tín hiệu từ các nguồn bằng chứng.'},
  {name:'SAST Scoring',short:'SCORING',icon:'Gauge',description:'Tính điểm heuristic theo policy và dữ liệu hiện có.'},
  {name:'Alert Triage',short:'TRIAGE',icon:'ShieldCheck',description:'Phân nhóm REPORT, REVIEW và SUPPRESS.'}
];

export default function AnalysisCore({phase=0,running=false,complete=false,onSelect}) {
  const [selected,setSelected]=useState(0);
  const active=running ? Math.max(0,Math.min(phase-1,modules.length-1)) : selected;
  const select=(index)=> {setSelected(index);onSelect?.(modules[index]);};
  return (
    <section className={`analysis-stage ${running ? 'is-running' : ''} ${complete ? 'is-complete' : ''}`}>
      <div className="analysis-stage-top">
        <div>
          <span className="analysis-kicker"><i /> ANALYSIS ENGINE · MÔ PHỎNG</span>
          <h2>{complete ? 'Pipeline đã hoàn tất' : running ? modules[active]?.name : 'Lõi phân tích đa tín hiệu'}</h2>
          <p>{complete ? 'Kịch bản minh họa đã đi qua các bước phân tích và triage.' : running ? modules[active]?.description : 'Các engine phối hợp quanh một luồng bằng chứng có thể giải thích.'}</p>
        </div>
        <span className={`engine-status ${running ? 'active' : complete ? 'complete' : ''}`}>
          <i />{complete ? 'HOÀN TẤT DEMO' : running ? 'ĐANG MÔ PHỎNG' : 'SẴN SÀNG'}
        </span>
      </div>
      <div className="engine-scene">
        <div className="scene-grid" />
        <div className="scene-depth depth-one" />
        <div className="scene-depth depth-two" />
        <div className="orbit orbit-a"><span /><span /><span /></div>
        <div className="orbit orbit-b"><span /><span /></div>
        <svg className="signal-lines" viewBox="0 0 800 440" aria-hidden="true">
          <defs>
            <linearGradient id="signal-gradient" x1="0" x2="1">
              <stop offset="0" stopColor="#38bdf8" stopOpacity=".06" />
              <stop offset=".5" stopColor="#38bdf8" stopOpacity=".9" />
              <stop offset="1" stopColor="#818cf8" stopOpacity=".16" />
            </linearGradient>
          </defs>
          <path d="M115 213 C205 213 220 180 315 188 S470 250 680 211" />
          <path d="M155 315 C270 300 272 250 370 240 S500 155 650 142" />
          <path d="M155 115 C255 130 270 195 350 200 S495 302 655 315" />
        </svg>
        <div className="source-port">
          <span className="port-icon"><Icon name="FolderGit2" /></span>
          <b>JAVA SOURCE</b><small>GitHub · ZIP · Inventory</small>
          <i className="port-beam" />
        </div>
        <motion.div className="neural-core" animate={running ? {scale:[1,1.035,1]} : {scale:[1,1.015,1]}} transition={{duration:running ? 1.3 : 3,repeat:Infinity,ease:'easeInOut'}}>
          <div className="core-ring core-ring-one" />
          <div className="core-ring core-ring-two" />
          <div className="core-mesh">
            {Array.from({length:18},(_,index)=> <i key={index} style={{'--node-index':index}} />)}
          </div>
          <div className="core-center"><Icon name="ScanSearch" /><b>SECURITY</b><small>ANALYSIS CORE</small></div>
          <span className="core-label">EVIDENCE ORCHESTRATION</span>
        </motion.div>
        <div className="module-orbit">
          {modules.map((module,index)=> (
            <motion.button
              key={module.name}
              className={`module-node node-${index} ${active===index ? 'selected' : ''} ${complete || phase>index+1 ? 'passed' : ''}`}
              onClick={()=> select(index)}
              whileHover={{scale:1.06,y:-2}}
              aria-label={`Xem vai trò ${module.name}`}
            >
              <span className="module-node-icon"><Icon name={module.icon} /></span>
              <span><b>{module.name}</b><small>{module.short}</small></span>
            </motion.button>
          ))}
        </div>
        <div className="output-port">
          <span className="port-icon"><Icon name="FileCheck2" /></span>
          <b>FINDINGS</b><small>Evidence · Triage · Report</small>
        </div>
        <div className="scene-particle particle-one" />
        <div className="scene-particle particle-two" />
        <div className="scene-particle particle-three" />
        <div className="scene-caption"><span>01</span> SOURCE INTAKE <i /> <span>02</span> MULTI-ENGINE ANALYSIS <i /> <span>03</span> AUDITABLE OUTPUT</div>
      </div>
      <div className="engine-bottom">
        <div className="active-module-detail">
          <span className="detail-icon"><Icon name={modules[active]?.icon || 'ScanSearch'} /></span>
          <div><small>THÀNH PHẦN ĐANG CHỌN</small><b>{modules[active]?.name}</b><p>{modules[active]?.description}</p></div>
        </div>
        <div className="triage-output">
          <span><i className="report-dot" />REPORT <b>{complete ? '01' : '—'}</b></span>
          <span><i className="review-dot" />REVIEW <b>{complete ? '02' : '—'}</b></span>
          <span><i className="suppress-dot" />SUPPRESS <b>{complete ? '01' : '—'}</b></span>
        </div>
      </div>
      <div className="engine-disclaimer">Sơ đồ và số đếm trong chế độ này là dữ liệu mô phỏng, không phải trạng thái xử lý từ backend.</div>
    </section>
  );
}