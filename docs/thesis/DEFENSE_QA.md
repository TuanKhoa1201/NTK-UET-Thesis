# BỘ CÂU HỎI VÀ TRẢ LỜI PHẢN BIỆN BẢO VỆ ĐỒ ÁN (DEFENSE_QA)

**Đề tài:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
**Tác giả:** Nguyễn Tuấn Khoa | **Hội đồng:** Đại học Công nghệ (VNU-UET)  
**Ngày chuẩn bị:** 13/10/2026  

---

### Câu hỏi 1: Tại sao đồ án lại lựa chọn thay thế Semgrep bằng OpenGrep?
**Trả lời:**
- Semgrep đã thay đổi mô hình cấp phép từ nguồn mở sang nguồn đóng độc quyền cho các tính năng nâng cao (Taint analysis, Pro engine).
- **OpenGrep** là nhánh phát triển mã nguồn mở chính thức (fork) giữ giấy phép tự do LGPL-2.1, bảo đảm hoàn toàn tính tự chủ về công nghệ, không phụ thuộc vào nhà cung cấp độc quyền và phù hợp với yêu cầu của Giảng viên hướng dẫn.
- Trong hệ thống NTK, OpenGrep 1.25.0 được cấu hình thuần túy (OpenGrep-only), loại bỏ hoàn toàn cơ chế fallback về Semgrep và tương thích 100% với chuẩn định dạng SARIF v2.1.0.

---

### Câu hỏi 2: Mô hình LLM trong đồ án đảm bảo tính riêng tư như thế nào đối với mã nguồn doanh nghiệp?
**Trả lời:**
- Đồ án thiết lập nguyên tắc **100% On-Premise Privacy**. Toàn bộ suy luận được thực hiện trên GPU cục bộ (NVIDIA GeForce RTX 4060 Ti 16GB) sử dụng mô hình nền tảng `Qwen2.5-Coder-1.5B-Instruct` kết hợp trọng số tinh chỉnh LoRA (73.9 MB) hoặc Ollama.
- Hệ thống áp dụng cơ chế `THESIS_LOCAL_ONLY_MODE` fail-closed: nếu có bất kỳ lệnh gọi nào hướng tới các dịch vụ Cloud API (OpenAI, Anthropic, OpenRouter), hệ thống sẽ chủ động ném ngoại lệ `PermissionError` và chặn đứng luồng dữ liệu ngay lập tức. Mã nguồn hoàn toàn không rời khỏi máy chủ nội bộ.

---

### Câu hỏi 3: Điểm rủi ro SAST Composite Scoring có phải là điểm CVSS/CWSS không? Cơ sở khoa học của nó là gì?
**Trả lời:**
- Điểm số của đồ án **không phải là CVSS hay CWSS chính thức**, mà là **Mô hình Chấm điểm Ưu tiên Rủi ro Dựa trên Bằng chứng Quan sát được (Observable Evidence Risk Scoring Framework)**.
- Điểm CVSS yêu cầu các tham số về môi trường mạng và tương tác người dùng chỉ có được sau khi lỗ hổng đã được xác nhận. Đối với cảnh báo SAST thô, mô hình của đồ án tổng hợp 4 thành phần quan sát được:
  1. $S_{eff}$: Mức độ nghiêm trọng tĩnh của quy tắc kết hợp hệ số điều chỉnh nội tại theo CWE.
  2. $P$: Độ chính xác khai báo của rule phân tích tĩnh.
  3. $C_{sem}$: Bằng chứng phân loại ngữ nghĩa vai trò hàm từ mô hình AI cục bộ (Sink, Source, Propagator, None).
  4. $E$: Bằng chứng luồng truyền dữ liệu vết (Taint Reachability).
- Điểm số áp dụng hệ số hạ bậc bảo thủ ($\gamma = 0.35$) đối với các cảnh báo nghi ngờ là báo động giả (`none`), giúp hạ ưu tiên của cảnh báo nhưng vẫn bảo toàn khả năng rà soát của chuyên viên an ninh.

---

### Câu hỏi 4: Tại sao trên tập kiểm thử 330 mẫu, độ chính xác toàn cục là 67.58% và F1 của lớp Taint-Propagator chỉ đạt 0.46?
**Trả lời:**
- Đây là kết quả thực nghiệm trung thực, độc lập trên tập 330 mẫu held-out (hoàn toàn không làm đẹp số liệu).
- Mô hình đạt hiệu năng rất cao trên hai lớp quan trọng nhất về an ninh: **Sink (F1 = 0.84, Precision 0.86)** và **Source (F1 = 0.76, Precision 0.89)**.
- Lớp `taint-propagator` có F1 = 0.46 (Recall 36.05%) do tính chất đa dạng của các hàm truyền dữ liệu trong Java (chuỗi, bộ sưu tập, luồng I/O). Với mô hình tham số nhỏ 1.5B phục vụ suy luận cục bộ thời gian thực, mô hình có xu hướng phân loại một số hàm tiện ích thành `none`.
- Trong kiến trúc hệ thống, nhược điểm này được bù đắp bởi Tầng 1 (OpenGrep dataflow analysis): nếu OpenGrep phát hiện taint trace có thực, thành phần $E = 1.0$ sẽ giữ điểm rủi ro ở mức cao mà không bị phụ thuộc duy nhất vào dự đoán của LLM.

---

### Câu hỏi 5: Nếu một phương thức được AI dự đoán là `none`, liệu cảnh báo đó có chắc chắn là False Positive không?
**Trả lời:**
- **Không.** Đồ án phân định rạch ròi giữa **Vai trò API (API Role)** và **Kết luận Lỗ hổng ở mức Cảnh báo (Finding-level Verdict)** nhằm tránh bẫy sai lệch Category Error.
- Một phương thức không phải là Sink đối với CWE này không có nghĩa cảnh báo đó là an toàn tuyệt đối, vì lỗ hổng có thể nằm ở một lời gọi hàm khác trong cùng khối mã.
- Do đó, khi AI dự đoán là `none`, trạng thái cảnh báo được gán là `SUSPECTED_FALSE_POSITIVE` (nghi ngờ báo động giả) với hệ số hạ bậc bảo thủ $\gamma = 0.35$, không bao giờ bị xóa bỏ hoặc ép về 0 điểm.
EOF
