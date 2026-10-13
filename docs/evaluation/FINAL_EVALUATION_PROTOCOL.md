# GIAO THỨC ĐÁNH GIÁ THỰC NGHIỆM ĐỘC LẬP (FINAL_EVALUATION_PROTOCOL)

**Đồ án Tốt nghiệp:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
**Hệ thống:** NTK / IRIS / simple_semgrepAI  
**Phiên bản giao thức:** NTK-EVAL-PROTO-202610-FINAL  
**Ngày ban hành:** 13/10/2026  

---

## 1. MỤC TIÊU VÀ NGUYÊN TẮC KHOA HỌC
Giao thức này thiết lập tiêu chuẩn kiểm định thực nghiệm nghiêm ngặt, độc lập và có khả năng tái lập hoàn toàn (Full Reproducibility), loại bỏ triệt để:
1. Không sử dụng dữ liệu giả lập (synthetic data) để tuyên bố hiệu quả thực nghiệm trên môi trường thực tế.
2. Không định sẵn nhãn dự đoán của AI dựa trên Ground Truth.
3. Không sửa đổi kết quả hoặc che giấu lỗi để đạt được chỉ số làm đẹp (no cosmetic metrics).
4. Phân định rõ ràng giữa hai bài toán:
   - **Bài toán Phân loại Ngữ nghĩa API (Stage 3 API-Role Classification):** Đánh giá khả năng của mô hình QLoRA trong việc nhận diện vai trò `source`, `sink`, `taint-propagator`, `none` của một API đối với CWE mục tiêu.
   - **Bài toán Xếp hạng Ưu tiên Cảnh báo SAST (SAST Risk Prioritization & Re-ranking):** Đánh giá khả năng của công thức chấm điểm V2.1 trong việc đẩy các lỗ hổng thật lên nhóm ưu tiên cao (Top-K) và hạ bậc các cảnh báo giả/vô hại xuống nhóm dưới.

---

## 2. THIẾT KẾ BỘ DỮ LIỆU ĐÁNH GIÁ (EVALUATION CORPUS)

### 2.1. Tập kiểm thử độc lập Stage 3 (Held-Out Test Set - 330 mẫu)
- **Nguồn gốc dữ liệu (Provenance):** Trích xuất từ các thư viện Java và dự án thực tế thông qua pipeline tiền xử lý `dataset_pipeline/`.
- **Phân bổ Ground Truth:**
  - `source`: 109 mẫu (33.03%)
  - `taint-propagator`: 86 mẫu (26.06%)
  - `none`: 76 mẫu (23.03%)
  - `sink`: 59 mẫu (17.88%)
- **Cơ chế chia tập (Split Protocol):** Tách biệt tập kiểm thử độc lập, bảo đảm không bị ô nhiễm bởi các mẫu ví dụ trong prompt (zero prompt collision).

### 2.2. Tập kiểm chứng End-to-End Vulnerable / Fixed Fixtures
- Sử dụng các kho mã nguồn Java thực tế có lịch sử CVE được xác nhận:
  - `mini_vulnerable_java_CVE-89_1.0` (SQLi, XXE, Command Injection, Insecure Deserialization, Path Traversal)
  - `jeecgboot_CVE-2025-51825_vuln` và `jeecgboot_CVE-2025-51825_fixed`
  - `metacat_CVE-2026-48528_vuln` và `metacat_CVE-2026-48528_fixed`

---

## 3. CHỈ SỐ ĐO LƯỜNG (METRICS SPECIFICATION)
1. **Per-class Precision, Recall, F1-score:** Đo lường hiệu năng trên từng lớp nhãn.
2. **Strict Overall Accuracy:** Tính trên toàn bộ 330 mẫu, trong đó mọi kết quả `unknown` hoặc lỗi định dạng JSON đều bị tính là dự đoán sai.
3. **Top-K Precision & False Positive Reduction Rate:** Đo lường tỷ lệ cảnh báo nguy hiểm trong Top-K sau khi tái sắp xếp bằng SAST Scoring Engine V2.1.
4. **Structured JSON Output Validity Rate:** Tỷ lệ sinh JSON tuân thủ đúng schema mà không cần fallback regex.
EOF
