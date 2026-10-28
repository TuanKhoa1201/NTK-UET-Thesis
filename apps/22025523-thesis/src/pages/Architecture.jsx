import {useState} from 'react';
import {Card,DataNotice,PageHeader,SectionTitle,Icon} from '../components/common/Ui';

const workflows=[
  {title:'A · Giai đoạn nghiên cứu và huấn luyện',tone:'violet',steps:['Nguồn dữ liệu','Provenance','Quality gates','Role annotation','LoRA fine-tuning','Evaluation','Checkpoint']},
  {title:'B · Giai đoạn phân tích mã nguồn',tone:'cyan',steps:['Java / ZIP','Inventory','OpenGrep','IRIS / AST','Qwen LoRA','Evidence Fusion','Scoring · Triage','Report']}
];

const components=[
  {name:'OpenGrep',icon:'ScanSearch',role:'Phát hiện ứng viên theo quy tắc',input:'Mã nguồn Java và bộ quy tắc phân tích tĩnh.',output:'Danh sách cảnh báo ứng viên gồm CWE,quy tắc,đường dẫn file,vị trí dòng và đoạn mã liên quan.',contribution:'Sàng lọc nhanh những vị trí cần phân tích sâu,giảm phạm vi công việc của các thành phần phía sau.',limitation:'Phát hiện dựa trên quy tắc có thể tạo cảnh báo giả khi thiếu ngữ cảnh thực thi và có thể bỏ sót vấn đề ngoài phạm vi ruleset.',explanation:'OpenGrep quét mã nguồn Java bằng quy tắc phân tích tĩnh để tìm vị trí có mẫu đáng nghi. Kết quả là candidate cần được bổ sung ngữ cảnh,không phải kết luận lỗ hổng tự động.'},
  {name:'IRIS / Java AST & Dataflow',icon:'GitBranch',role:'Phân tích cấu trúc và bằng chứng chương trình',input:'Cảnh báo ứng viên từ OpenGrep và ngữ cảnh mã nguồn Java liên quan.',output:'Bằng chứng AST,trạng thái phân tích luồng dữ liệu,bằng chứng xử lý an toàn và lý do cần xem xét.',contribution:'Giúp phân biệt mẫu mã đáng nghi với trường hợp có bằng chứng rõ hơn về luồng dữ liệu nguy hiểm hoặc cách xử lý an toàn.',limitation:'Phạm vi tập trung vào phân tích nội thủ tục và cấu trúc được hỗ trợ. Luồng phức tạp qua nhiều phương thức,lớp hoặc trạng thái động có thể chưa được chứng minh đầy đủ. AST hiện dựa trên OpenJDK JavacTask ở nơi được hỗ trợ;đây không phải xác minh ngữ nghĩa toàn diện cho mọi chương trình Java.',explanation:'IRIS xem xét cấu trúc chương trình và các bằng chứng luồng dữ liệu mà triển khai hỗ trợ. Kết quả giúp kiểm tra ngữ cảnh quanh cảnh báo,nhưng phạm vi phân tích có giới hạn.'},
  {name:'Qwen + LoRA',icon:'Cpu',role:'Phân loại vai trò API',input:'Ngữ cảnh API Java được chuẩn hóa theo định dạng suy luận của hệ thống.',output:'Nhãn source,sink,taint-propagator hoặc none cùng metadata nếu có.',contribution:'Bổ sung tín hiệu ngữ nghĩa cho các trường hợp mà quy tắc tĩnh chưa đủ rõ.',limitation:'Dự đoán có thể sai và không tự chứng minh lỗ hổng. Metrics fine-tuning đo phân loại API role,không phải độ chính xác phát hiện lỗ hổng toàn hệ thống.',explanation:'Mô hình Qwen được fine-tune bằng LoRA để phân loại vai trò API. Tín hiệu này bổ trợ đánh giá;nó không tự xác nhận hay loại trừ một lỗ hổng.'},
  {name:'Evidence Fusion',icon:'Share2',role:'Hợp nhất nguồn bằng chứng',input:'Scanner findings,bằng chứng AST/dataflow và dự đoán vai trò API.',output:'Bộ tín hiệu hợp nhất phục vụ scoring và phân loại cảnh báo.',contribution:'Giảm phụ thuộc vào một công cụ duy nhất và lưu nguồn gốc từng loại bằng chứng.',limitation:'Khi tín hiệu mâu thuẫn hoặc thiếu dữ liệu,hệ thống cần giữ trạng thái chưa chắc chắn thay vì suy diễn kết luận tuyệt đối.',explanation:'Lớp hợp nhất giữ các tín hiệu và provenance từ nhiều thành phần để scoring và triage có cơ sở giải thích hơn.'},
  {name:'SAST Scoring',icon:'Gauge',role:'Đánh giá heuristic theo policy',input:'Base scanner score,vai trò API,trạng thái bằng chứng AST và điều kiện safety floor.',output:'Điểm cuối,giải thích các điều chỉnh và metadata chính sách.',contribution:'Hỗ trợ ưu tiên và giải thích cảnh báo một cách nhất quán.',limitation:'Hệ số là tham số heuristic do hệ thống nghiên cứu thiết kế. Điểm số không thay thế xác minh bằng chứng hoặc đánh giá thủ công.',explanation:'Policy heuristic biến các tín hiệu được chọn thành điểm hỗ trợ ưu tiên và giải thích;điểm không phải xác suất thống kê.'},
  {name:'Alert Verification & Triage',icon:'ShieldCheck',role:'Phân luồng cảnh báo theo bằng chứng',input:'Finding,score breakdown,bằng chứng AST và các tín hiệu liên quan.',output:'REPORT,REVIEW hoặc SUPPRESS cùng reason codes và audit trail.',contribution:'Ưu tiên cảnh báo cần xử lý mà vẫn giữ trường hợp chưa chắc chắn để kiểm tra.',limitation:'REPORT chưa phải chuyên gia xác nhận;SUPPRESS không chứng minh phần mềm an toàn. Trạng thái CONFIRMED chỉ thuộc quy trình review có chứng cứ.',explanation:'Triage chuyển bằng chứng thành luồng xử lý REPORT,REVIEW hoặc SUPPRESS,đồng thời giữ trạng thái cần review thay vì kết luận vượt quá dữ liệu.'}
];

export default function ArchitecturePage() {
  const [selected,setSelected]=useState(0);
  const item=components[selected];
  return (
    <>
      <PageHeader eyebrow="NỀN TẢNG" title="Kiến trúc hệ thống" description="Hai giai đoạn nghiên cứu và vận hành được tách biệt;mỗi thành phần có đầu vào,đầu ra,đóng góp và giới hạn riêng." />
      {workflows.map((workflow,index)=> <Workflow key={workflow.title} workflow={workflow} index={index} />)}
      <section className="section-block architecture-roles">
        <SectionTitle title="Vai trò và giới hạn của các thành phần" />
        <div className="architecture-explorer">
          <nav className="architecture-selector" aria-label="Thành phần kiến trúc">
            {components.map((component,index)=> (
              <button key={component.name} className={selected===index ? 'active' : ''} onClick={()=> setSelected(index)}>
                <span className="selector-number">{String(index+1).padStart(2,'0')}</span>
                <span className="selector-icon"><Icon name={component.icon} /></span>
                <span className="selector-label"><b>{component.name}</b><small>{component.role}</small></span>
                <Icon name="ChevronRight" />
              </button>
            ))}
          </nav>
          <Card className="architecture-explanation">
            <div className="explanation-title">
              <span><Icon name={item.icon} /></span>
              <div><small>THÀNH PHẦN {String(selected+1).padStart(2,'0')}</small><h2>{item.name}</h2><p>{item.role}</p></div>
            </div>
            <div className="architecture-description"><h3>Vai trò trong hệ thống</h3><p>{item.explanation}</p></div>
            <div className="io-grid">
              <InfoBlock title="Đầu vào" text={item.input} icon="LogIn" />
              <InfoBlock title="Đầu ra" text={item.output} icon="LogOut" />
            </div>
            <div className="contribution-limit">
              <InfoBlock title="Đóng góp" text={item.contribution} icon="Target" />
              <InfoBlock title="Giới hạn" text={item.limitation} icon="TriangleAlert" />
            </div>
          </Card>
        </div>
      </section>
      <DataNotice>REPORT là trạng thái ưu tiên theo policy,không phải xác nhận chuyên gia. SUPPRESS vẫn được lưu trong audit trail.</DataNotice>
    </>
  );
}

function Workflow({workflow,index}) {
  return (
    <section className={`architecture-workflow architecture-lane ${workflow.tone}`}>
      <div className="lane-heading"><span>{String(index+1).padStart(2,'0')}</span><h2>{workflow.title}</h2><i /></div>
      <div className="workflow-grid">
        {workflow.steps.map((step,stepIndex)=> (
          <div className="workflow-step" key={step}>
            <span>{String(stepIndex+1).padStart(2,'0')}</span>
            <b>{step}</b>
            {stepIndex<workflow.steps.length-1 && <Icon name="ArrowRight" />}
          </div>
        ))}
      </div>
    </section>
  );
}

function InfoBlock({title,text,icon}) {
  return <div className="architecture-info"><span><Icon name={icon} /></span><div><h3>{title}</h3><p>{text}</p></div></div>;
}