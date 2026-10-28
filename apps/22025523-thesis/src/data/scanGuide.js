export const scanGuide=[
  {
    title:'Tiếp nhận dự án',
    purpose:'Nhận repository hoặc tệp ZIP làm đầu vào cho phiên phân tích.',
    input:'URL GitHub công khai hoặc archive ZIP do người dùng chọn.',
    process:'Tiếp nhận nguồn mã; việc kiểm tra và giải nén an toàn thuộc backend.',
    output:'Nguồn dự án và thông tin đầu vào của phiên.',
    meaning:'Xác định đối tượng phân tích mà không thực thi mã Java được tải lên.',
    icon:'FolderGit2',
    visual:'intake'
  },
  {
    title:'Lập danh mục mã nguồn',
    purpose:'Xác định file Java và phạm vi mã nguồn cần đưa vào pipeline.',
    input:'Repository hoặc archive đã được backend tiếp nhận.',
    process:'Lập danh sách file, package và các nội dung nằm ngoài phạm vi.',
    output:'Danh mục mã nguồn và phạm vi phân tích.',
    meaning:'Giúp báo cáo minh bạch phần nào đã được xử lý hoặc bỏ qua.',
    icon:'Files',
    visual:'inventory'
  },
  {
    title:'OpenGrep — Phát hiện ứng viên',
    purpose:'Tìm các mẫu mã nguồn có dấu hiệu rủi ro theo quy tắc.',
    input:'Mã nguồn Java và ruleset phân tích tĩnh.',
    process:'Quét mẫu, đối chiếu quy tắc và thu thập vị trí khớp.',
    output:'Candidate findings kèm CWE, rule và vị trí mã.',
    meaning:'Sàng lọc vị trí cần phân tích sâu; candidate chưa phải kết luận.',
    icon:'ScanSearch',
    visual:'opengrep'
  },
  {
    title:'Trích xuất ngữ cảnh',
    purpose:'Chuẩn bị đoạn mã và thông tin API liên quan tới candidate.',
    input:'Vị trí cảnh báo và mã nguồn Java xung quanh.',
    process:'Thu thập cấu trúc và ngữ cảnh cần cho các thành phần tiếp theo.',
    output:'Ngữ cảnh mã nguồn được chuẩn hóa.',
    meaning:'Giúp phân tích các bằng chứng trong đúng bối cảnh chương trình.',
    icon:'Code2',
    visual:'context'
  },
  {
    title:'IRIS — Phân tích chương trình',
    purpose:'Bổ sung ngữ cảnh cấu trúc và bằng chứng chương trình được hỗ trợ.',
    input:'Candidate findings và ngữ cảnh Java.',
    process:'Phân tích cấu trúc AST, trạng thái dataflow và bằng chứng xử lý an toàn khi có.',
    output:'Bằng chứng phân tích cùng các giới hạn hoặc trạng thái chưa rõ.',
    meaning:'Hỗ trợ phân biệt mẫu đáng nghi với trường hợp có thêm căn cứ.',
    icon:'GitBranch',
    visual:'iris'
  },
  {
    title:'Qwen LoRA — Phân loại API',
    purpose:'Nhận diện vai trò API trong ngữ cảnh bảo mật.',
    input:'Ngữ cảnh API Java đã chuẩn hóa.',
    process:'Mô hình fine-tuned dự đoán source, sink, taint-propagator hoặc none.',
    output:'Nhãn vai trò và metadata được backend cung cấp.',
    meaning:'Bổ sung tín hiệu ngữ nghĩa; dự đoán không tự chứng minh vulnerability.',
    icon:'Cpu',
    visual:'qwen'
  },
  {
    title:'Hợp nhất bằng chứng',
    purpose:'Tập hợp tín hiệu từ scanner, phân tích chương trình và mô hình.',
    input:'OpenGrep findings, IRIS evidence và API role prediction.',
    process:'Giữ nguồn gốc các tín hiệu để phục vụ scoring và giải thích.',
    output:'Bản ghi evidence hợp nhất.',
    meaning:'Giảm phụ thuộc vào một nguồn đơn lẻ và làm rõ điểm chưa chắc chắn.',
    icon:'Share2',
    visual:'fusion'
  },
  {
    title:'Chấm điểm SAST',
    purpose:'Tính điểm heuristic theo scoring policy của hệ thống.',
    input:'Điểm nền, điều chỉnh theo role và bằng chứng AST liên quan.',
    process:'Áp dụng các nhánh policy, bao gồm safety floor hoặc safe release khi hợp lệ.',
    output:'Final heuristic score cùng breakdown.',
    meaning:'Hỗ trợ ưu tiên và giải thích; điểm không phải xác suất vulnerability.',
    icon:'Gauge',
    visual:'scoring'
  },
  {
    title:'Xác minh cảnh báo',
    purpose:'Phân luồng finding theo bằng chứng và điều kiện triage.',
    input:'Finding, score breakdown, evidence và policy metadata.',
    process:'Đánh giá điều kiện REPORT, REVIEW hoặc SUPPRESS.',
    output:'Quyết định triage và reason codes; dữ liệu vẫn có thể được audit.',
    meaning:'Hướng sự chú ý tới cảnh báo cần xử lý mà không khẳng định quá mức.',
    icon:'ShieldCheck',
    visual:'triage'
  },
  {
    title:'Tổng hợp báo cáo',
    purpose:'Tổng hợp findings và giới hạn của phiên phân tích.',
    input:'Trạng thái scan và kết quả do backend cung cấp.',
    process:'Tổ chức metrics, findings, evidence và phạm vi coverage.',
    output:'Báo cáo phiên phân tích có thể xem lại.',
    meaning:'Trình bày kết quả trong đúng phạm vi đã xử lý.',
    icon:'FileText',
    visual:'report'
  }
];