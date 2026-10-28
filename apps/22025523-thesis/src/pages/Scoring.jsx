import {useMemo,useState} from 'react';
import {Card,DataNotice,PageHeader,SectionTitle,Badge,Icon} from '../components/common/Ui';

const roleAdjustments={sink:0.15,none:-0.35,source:0,'taint-propagator':0};

export default function ScoringPage() {
  const [baseScore,setBaseScore]=useState(0.7);
  const [role,setRole]=useState('sink');
  const [floorEnabled,setFloorEnabled]=useState(true);
  const [safeRelease,setSafeRelease]=useState(false);
  const rawScore=clamp(baseScore+roleAdjustments[role]);
  const finalScore=safeRelease ? 0 : floorEnabled ? Math.max(rawScore,0.55) : rawScore;
  const floorUsed=!safeRelease && floorEnabled && rawScore<0.55;
  const calculation=useMemo(()=> [
    {title:'Điểm nền scanner',value:baseScore,reason:'Candidate từ phân tích tĩnh',color:'base'},
    {title:'Điều chỉnh LLM',value:roleAdjustments[role],reason:`Vai trò API: ${role}`,color:roleAdjustments[role]<0 ? 'negative' : 'llm'},
    {title:safeRelease ? 'AST safe release' : floorUsed ? 'Safety floor' : 'Bảo toàn điểm',value:safeRelease ? 0 : floorUsed ? 0.55 : rawScore,reason:safeRelease ? 'Backend xác nhận policy safe-release' : floorUsed ? 'S_final=max(S_raw,0.55)' : 'Không có nhánh điều chỉnh bổ sung',color:safeRelease ? 'safe' : 'guard'}
  ],[baseScore,role,safeRelease,floorUsed,rawScore]);

  return (
    <>
      <PageHeader eyebrow="PHƯƠNG PHÁP" title="Chấm điểm dựa trên bằng chứng" description="Giải thích công thức, nguồn gốc các hệ số và cơ chế ra quyết định cảnh báo của hệ thống." />
      <DataNotice>Cơ chế SAST Scoring là chính sách heuristic phục vụ hợp nhất bằng chứng. Điểm không phải xác suất lỗ hổng đã hiệu chuẩn và không phải điểm CVSS. Backend là nguồn quyết định cuối cùng.</DataNotice>
      <section className="section-block scoring-rationale">
        <SectionTitle title="Vì sao hệ thống cần chấm điểm?" />
        <Card><p>Công cụ phân tích tĩnh có thể phát hiện một mẫu mã nguồn đáng nghi nhưng chưa đủ bằng chứng để khẳng định đây là lỗ hổng thực tế. Vì vậy, hệ thống cần tổng hợp thêm tín hiệu từ phân tích cấu trúc chương trình và mô hình ngôn ngữ.</p><p>Cơ chế chấm điểm biểu diễn mức đánh giá theo một chính sách thống nhất để hỗ trợ giải thích và ưu tiên kiểm tra. Quyết định xử lý cuối cùng vẫn phải xét bằng chứng và quy tắc triage.</p></Card>
      </section>
      <section className="section-block">
        <SectionTitle title="Thứ tự xử lý theo policy" text="Các nhánh dưới đây mô tả chính sách hiện được báo cáo; điều kiện production lấy từ phiên bản backend." />
        <div className="formula-card policy-formula-grid">
          <FormulaStep number="01" title="Tính điểm nền và điều chỉnh vai trò" label="BASE + ROLE">
            <div className="math-display">S<sub>raw</sub> = clamp(S<sub>base</sub> + Δ<sub>LLM</sub>, 0, 1)</div>
            <p><b>S<sub>base</sub> = 0.70</b>; Δ<sub>LLM</sub> là điều chỉnh theo nhãn vai trò API.</p>
          </FormulaStep>
          <FormulaStep number="02" title="Kiểm tra safe release đã xác minh" label="VERIFIED SAFE RELEASE">
            <div className="math-display compact">S<sub>final</sub> = 0</div>
            <p>Chỉ khi bằng chứng AST đáng tin cậy đáp ứng điều kiện safe-release của backend.</p>
          </FormulaStep>
          <FormulaStep number="03" title="Áp dụng safety floor khi cần" label="SAFETY FLOOR">
            <div className="math-display compact">S<sub>final</sub> = max(S<sub>raw</sub>, 0.55)</div>
            <p>Khi policy yêu cầu bảo toàn cảnh báo và không có safe-release hợp lệ.</p>
          </FormulaStep>
          <FormulaStep number="04" title="Giữ điểm đã tính" label="OTHERWISE">
            <div className="math-display compact">S<sub>final</sub> = S<sub>raw</sub></div>
            <p>Nếu không áp dụng hai nhánh trên, giữ điểm trong phạm vi từ 0 đến 1.</p>
          </FormulaStep>
        </div>
      </section>

      <div className="scoring-grid">
        <Card title="Tham số chính sách hiện được báo cáo">
          <div className="parameter-list">
            <Parameter name="Base scanner score" value="0.70" note="Điểm nền của candidate theo policy." />
            <Parameter name="LLM role=sink" value="+0.15" note="Tín hiệu tăng khi API gắn với thao tác nhạy cảm." />
            <Parameter name="LLM role=none" value="−0.35" note="Tín hiệu giảm; có thể được giới hạn bởi safety floor." />
            <Parameter name="source / không điều chỉnh" value="0.00" note="Không thêm hoặc trừ điểm từ nhánh role." />
            <Parameter name="Safety floor" value="0.55" note="Sàn có điều kiện để tránh giảm quá mức khi còn rủi ro chưa giải quyết." />
          </div>
        </Card>
        <Card title="Cơ sở lựa chọn công thức và hệ số">
          <p>Công thức được xây dựng theo hướng heuristic có thể giải thích, phù hợp mục tiêu hợp nhất nhiều nguồn bằng chứng.</p>
          <p>Điểm nền 0.70 là mức khởi đầu do policy gán cho cảnh báo ứng viên. +0.15 tăng điểm khi mô hình nhận diện API có vai trò sink. −0.35 giảm điểm khi mô hình dự đoán none, nhưng mô hình không phải nguồn xác minh an toàn tuyệt đối.</p>
          <p>Safety floor 0.55 giữ lại một số trường hợp chưa đủ cơ sở kết luận an toàn, nhất là khi có rủi ro cao hoặc bằng chứng xung đột. Chỉ điều kiện AST do backend xác minh mới có thể kích hoạt safe-release về 0.</p>
          <p className="research-caveat">Đây là lựa chọn thiết kế heuristic. Chưa có căn cứ để nói hệ số được suy ra từ CVSS, tối ưu hóa thống kê hoặc một chuẩn bên ngoài. Cần dẫn artifact nghiên cứu nếu có hiệu chỉnh bổ sung.</p>
        </Card>
      </div>

      <section className="section-block">
        <SectionTitle title="Minh họa chính sách chấm điểm" text="Bộ tính tương tác giải thích phép biến đổi; không thay thế scoring engine backend." />
        <div className="calculator-layout">
          <Card title="Tham số minh họa">
            <label className="calculator-control">Base score <b>{baseScore.toFixed(2)}</b><input type="range" min="0" max="1" step="0.01" value={baseScore} onChange={(event)=> setBaseScore(Number(event.target.value))} /></label>
            <label className="calculator-control">Vai trò API<select value={role} onChange={(event)=> setRole(event.target.value)}><option value="sink">sink · +0.15</option><option value="none">none · −0.35</option><option value="source">source · 0.00</option><option value="taint-propagator">taint-propagator · 0.00</option></select></label>
            <label className="check-control"><input type="checkbox" checked={floorEnabled} onChange={(event)=> setFloorEnabled(event.target.checked)} /> Điều kiện safety floor áp dụng</label>
            <label className="check-control safe-check"><input type="checkbox" checked={safeRelease} onChange={(event)=> setSafeRelease(event.target.checked)} /> Backend đã xác minh AST safe-release</label>
            <p className="calculator-warning">Chỉ bật safe-release khi backend xác nhận điều kiện. Bộ minh họa không xác minh mã nguồn.</p>
          </Card>
          <Card className="calculator-result" title="Waterfall giải thích">
            <div className="waterfall-list">{calculation.map((step,index)=> <div className={`waterfall-row ${step.color}`} key={step.title}><span>{String(index+1).padStart(2,'0')}</span><div><b>{step.title}</b><small>{step.reason}</small></div><strong>{step.value>=0 ? '+' : ''}{step.value.toFixed(2)}</strong></div>)}</div>
            <div className="final-score"><span>S<sub>raw</sub> · {rawScore.toFixed(2)}</span><Icon name="ArrowRight" /><span>S<sub>final</sub></span><b>{finalScore.toFixed(2)}</b></div>
            <div className="score-track"><i style={{width:`${finalScore*100}%`}} /></div>
            <p>{safeRelease ? 'Điểm minh họa được giải phóng theo điều kiện AST đã chọn.' : floorUsed ? 'Safety floor giữ điểm cuối tối thiểu ở 0.55 trong ví dụ.' : 'Không áp dụng safety floor trong ví dụ hiện tại.'}</p>
          </Card>
        </div>
      </section>

      <section className="section-block">
        <SectionTitle title="Bốn trường hợp diễn giải" text="Ví dụ giải thích policy, không phải kết quả của một phiên scan thực tế." />
        <div className="worked-grid">
          <Worked title="A · API role sink" formula="0.70 + 0.15 = 0.85" result="S_raw = 0.85" text="Sink làm tăng điểm. Chỉ riêng dự đoán sink chưa đủ xác nhận lỗ hổng; cần xét evidence IRIS/AST và triage." tone="cyan" />
          <Worked title="B · Mô hình dự đoán none" formula="0.70 − 0.35 = 0.35" result="max(0.35, 0.55) = 0.55*" text="Nếu safety-floor condition kích hoạt, cảnh báo được giữ lại để xem xét. Không tự động gán SUPPRESS." tone="amber" />
          <Worked title="C · AST safe release" formula="Verified safe-release → 0.00" result="SUPPRESS theo policy" text="Chỉ áp dụng khi backend xác nhận điều kiện AST. Bản ghi vẫn ở audit trail; điều này không chứng minh toàn dự án an toàn." tone="green" />
          <Worked title="D · Thiếu bằng chứng" formula="Không đủ trace / tín hiệu mâu thuẫn" result="REVIEW khi policy yêu cầu" text="Giữ cảnh báo cho kiểm tra thủ công thay vì suy diễn kết luận đúng hoặc sai từ score đơn lẻ." tone="violet" />
        </div>
        <p className="scoring-footnote">* Safety floor phụ thuộc điều kiện policy; ví dụ không khẳng định nhánh này luôn áp dụng.</p>
      </section>

      <section className="section-block">
        <SectionTitle title="Score ≠ Severity ≠ Triage Decision" text="Ba khái niệm liên quan nhưng không thể thay thế lẫn nhau." />
        <div className="concept-grid">
          <Concept title="Heuristic score" icon="Gauge" text="Điểm tổng hợp tín hiệu theo policy. Không phải xác suất vulnerability đã hiệu chuẩn." />
          <Concept title="Severity" icon="TriangleAlert" text="Mức độ nghiêm trọng của loại vấn đề theo nguồn/ruleset tương ứng; không nói cảnh báo chắc chắn đúng." />
          <Concept title="Triage decision" icon="GitPullRequestArrow" text="REPORT, REVIEW hoặc SUPPRESS dựa trên evidence và điều kiện policy, không chỉ dựa trên ngưỡng score." />
        </div>
      </section>
      <Card className="triage-policy" title="Luồng quyết định cảnh báo">
        <div className="triage-policy-grid">
          <Decision title="REPORT" tone="report" text="Bằng chứng và điều kiện xác minh phù hợp với policy, chẳng hạn taint-flow được hỗ trợ. Đây vẫn không đồng nghĩa chuyên gia đã xác nhận." />
          <Decision title="REVIEW" tone="review" text="Bằng chứng thiếu, mâu thuẫn hoặc nằm ngoài phạm vi phân tích chắc chắn; cần người kiểm tra." />
          <Decision title="SUPPRESS" tone="suppress" text="Trusted AST evidence đáp ứng safe-release rule. Finding vẫn được lưu để audit." />
        </div>
        <p className="review-status-note">NOT_REVIEWED là trạng thái chưa được người kiểm tra xác nhận. CONFIRMED_TRUE_POSITIVE và CONFIRMED_FALSE_POSITIVE chỉ thuộc quy trình review thủ công có chứng cứ.</p>
      </Card>
      <DataNotice>Đây là biểu diễn diễn giải của policy được báo cáo. Điều kiện từng nhánh, evidence hợp lệ và quyết định cuối phải lấy từ phiên bản policy metadata/backend đã nghiệm thu.</DataNotice>
    </>
  );
}

function FormulaStep({number,title,label,children}) {
  return <article className="policy-step">
    <div className="policy-step-head"><span>{number}</span><div><small>{label}</small><h3>{title}</h3></div></div>
    {children}
  </article>;
}
function clamp(value) {return Math.min(1,Math.max(0,value));}
function Parameter({name,value,note}) {return <div className="parameter-row"><div><b>{name}</b><small>{note}</small></div><strong>{value}</strong></div>;}
function Worked({title,formula,result,text,tone}) {return <Card className={`worked-example ${tone}`} title={title}><div className="worked-formula">{formula}</div><strong>{result}</strong><p>{text}</p></Card>;}
function Concept({title,icon,text}) {return <Card className="scoring-concept"><span><Icon name={icon} /></span><h3>{title}</h3><p>{text}</p></Card>;}
function Decision({title,tone,text}) {return <div className={`decision-card ${tone}`}><Badge tone={tone==='report' ? 'red' : tone==='review' ? 'amber' : 'green'}>{title}</Badge><p>{text}</p></div>;}