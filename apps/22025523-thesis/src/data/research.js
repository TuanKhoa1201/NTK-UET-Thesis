export const navGroups = [
  {
    title: 'ỨNG DỤNG PHÂN TÍCH',
    items: [
      ['/', 'Tổng quan', 'Grid'],
      ['/scanner', 'Phân tích dự án', 'Scan'],
      ['/history', 'Lịch sử phân tích', 'Clock'],
      ['/findings', 'Kết quả phát hiện', 'Bug'],
      ['/review', 'Xác minh cảnh báo', 'Shield'],
      ['/reports', 'Báo cáo', 'FileText']
    ]
  },
  {
    title: 'NỀN TẢNG & PHƯƠNG PHÁP',
    items: [
      ['/architecture', 'Kiến trúc hệ thống', 'GitBranch'],
      ['/dataset', 'Dữ liệu nghiên cứu', 'Database'],
      ['/training', 'Quy trình huấn luyện', 'Cpu'],
      ['/scoring', 'Phương pháp chấm điểm', 'Sliders'],
      ['/evaluation', 'Đánh giá thực nghiệm', 'BarChart']
    ]
  },
  {
    title: 'HỆ THỐNG',
    items: [
      ['/status', 'Trạng thái hệ thống', 'Activity'],
      ['/about', 'Giới thiệu đề tài', 'Info']
    ]
  }
];

export const trainingResults = [
  { split: 'Development · 166', accuracy: 98.8, f1: 98.28 },
  { split: 'Historical V2 · 41', accuracy: 82.93, f1: 51.77 },
  { split: 'Historical V3 · 80', accuracy: 82.5, f1: 67.97 }
];

export const benchmarkRows = [
  { name: 'OpenGrep-only', tp: 9, fp: 8, fn: 1, precision: 52.94, recall: 90, f1: 66.67 },
  { name: 'OpenGrep + IRIS', tp: 9, fp: 1, fn: 1, precision: 90, recall: 90, f1: 90 },
  { name: 'OpenGrep + IRIS + LLM + Fusion', tp: 9, fp: 1, fn: 1, precision: 90, recall: 90, f1: 90 },
  { name: 'Full Triage · REPORT only', tp: 9, fp: 0, fn: 1, precision: 100, recall: 90, f1: 94.74 }
];

export const pipelinePhases = [
  ['Tiếp nhận dự án', 'Kiểm tra nguồn đầu vào và tạo phiên phân tích.', 'Archive'],
  ['Lập danh mục mã nguồn', 'Nhận diện file Java, cấu trúc package và phạm vi.', 'FolderTree'],
  ['OpenGrep Static Analysis', 'Tìm candidate dựa trên ruleset phân tích tĩnh.', 'Scan'],
  ['Trích xuất ngữ cảnh', 'Chuẩn bị thông tin cấu trúc cần cho phân tích tiếp theo.', 'Code'],
  ['IRIS Program Analysis', 'Bổ sung ngữ cảnh Java và bằng chứng luồng dữ liệu.', 'GitBranch'],
  ['Language Model Inference', 'Phân loại vai trò API: source, sink, propagator hoặc none.', 'Cpu'],
  ['Evidence Fusion', 'Kết hợp tín hiệu; không xem một nguồn đơn lẻ là kết luận tuyệt đối.', 'Share'],
  ['SAST Scoring', 'Tính điểm heuristic theo policy và bằng chứng hiện có.', 'Sliders'],
  ['Alert Verification', 'Phân loại cảnh báo thành REPORT, REVIEW hoặc SUPPRESS.', 'Shield'],
  ['Hoàn tất & báo cáo', 'Tổng hợp kết quả trong phạm vi phiên phân tích.', 'FileText']
];

export const demoFindings = [
  { id: 'VS-DEMO-014', cwe: 'CWE-089', title: 'SQL Injection candidate', file: 'src/main/java/app/UserRepository.java', line: 84, severity: 'High', score: 0.85, decision: 'REPORT', role: 'sink', reason: 'SQL query sử dụng dữ liệu đầu vào trong ngữ cảnh truy vấn.' },
  { id: 'VS-DEMO-011', cwe: 'CWE-078', title: 'OS Command Injection candidate', file: 'src/main/java/app/ProcessRunner.java', line: 42, severity: 'High', score: 0.72, decision: 'REVIEW', role: 'source', reason: 'Có candidate từ ruleset; cần xác minh đường đi dữ liệu.' },
  { id: 'VS-DEMO-009', cwe: 'CWE-079', title: 'Cross-Site Scripting candidate', file: 'src/main/java/app/view/Renderer.java', line: 117, severity: 'Medium', score: 0.48, decision: 'SUPPRESS', role: 'none', reason: 'Dữ liệu đầu ra được xử lý trong ngữ cảnh minh họa; cần đối chiếu policy.' },
  { id: 'VS-DEMO-006', cwe: 'CWE-022', title: 'Path Traversal candidate', file: 'src/main/java/app/FileService.java', line: 63, severity: 'Medium', score: 0.64, decision: 'REVIEW', role: 'taint-propagator', reason: 'Bằng chứng hiện có chưa đủ để kết luận.' }
];

export const datasetSamples = [
  { id: 'DEMO-001', cwe: 'CWE-089', family: 'JDBC', package: 'java.sql', className: 'Statement', method: 'executeQuery', signature: '(String)', role: 'sink', split: 'Minh họa' },
  { id: 'DEMO-002', cwe: 'CWE-078', family: 'Process', package: 'java.lang', className: 'Runtime', method: 'exec', signature: '(String)', role: 'sink', split: 'Minh họa' },
  { id: 'DEMO-003', cwe: 'CWE-079', family: 'Servlet', package: 'jakarta.servlet', className: 'HttpServletRequest', method: 'getParameter', signature: '(String)', role: 'source', split: 'Minh họa' },
  { id: 'DEMO-004', cwe: 'CWE-022', family: 'File', package: 'java.io', className: 'File', method: 'getCanonicalPath', signature: '()', role: 'taint-propagator', split: 'Minh họa' },
  { id: 'DEMO-005', cwe: 'CWE-089', family: 'JDBC', package: 'java.sql', className: 'PreparedStatement', method: 'setString', signature: '(int, String)', role: 'none', split: 'Minh họa' }
];

export const roleLabels = ['source', 'sink', 'taint-propagator', 'none'];