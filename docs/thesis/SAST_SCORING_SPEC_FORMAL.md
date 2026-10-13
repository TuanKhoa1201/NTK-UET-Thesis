# ĐẶC TẢ KHOA HỌC: MÔ HÌNH CHẤM ĐIỂM RỦI RO SAST TÍCH HỢP AI (COMPOSITE RISK SCORING MODEL)

**Đồ án Tốt nghiệp:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
**Tác giả:** Tuấn Khoa  
**Phiên bản:** SAST-SCORING-V2-FORMAL (2026-10-13)  
**Trạng thái:** HOÀN THIỆN & ĐÃ KIỂM ĐỊNH THỰC NGHIỆM (100% PASS)

---

## 1. TỔNG QUAN VÀ ĐỘNG LỰC NGHIÊN CỨU

Trong các công cụ SAST truyền thống (như OpenGrep / Semgrep), mức độ nghiêm trọng của một cảnh báo (`severity`) thường được định nghĩa tĩnh trong metadata của từng rule (`INFO`, `WARNING`, `ERROR`). Cơ chế này có **3 nhược điểm cốt tử**:
1. **Thiếu tính động (Static Rigidity):** Không phản ánh được ngữ cảnh thực thi thực tế của hàm mục tiêu (hàm có nhận dữ liệu từ người dùng bên ngoài hay chỉ nhận tham số nội bộ).
2. **Tỷ lệ báo động giả cao (High False Positive Rate):** Nhiều hàm có chữ ký giống sink nguy hiểm nhưng thực tế được gọi an toàn (đã qua sanitizer hoặc nằm trong test code/debug), dẫn đến cảnh báo tràn ngập làm quá tải chuyên viên bảo mật (Alert Fatigue).
3. **Thiếu chỉ số định lượng liên thông:** Không kết hợp được độ tin cậy từ các mô hình AI/LLM mới nhằm tái ưu tiên (re-ranking) các cảnh báo theo thứ tự ưu tiên xử lý.

Mô hình **SAST Composite Risk Scoring** được thiết kế dựa trên các nguyên lý chuẩn tắc của **MITRE CWSS (Common Weakness Scoring System)** và **CVSS v3.1**, kết hợp trực tiếp với kết quả thẩm định luồng dữ liệu của mô hình LLM fine-tuned chạy cục bộ.

---

## 2. KIẾN TRÚC MÔ HÌNH TOÁN HỌC

Điểm rủi ro tổng hợp $RiskScore \in [0.0, 100.0]$ được xác định qua công thức 2 tầng:

### Tầng 1: Điểm rủi ro cơ sở (Raw Score)
$$RawScore = 100 \times \left( w_s \cdot S_{eff} + w_p \cdot P + w_a \cdot C_{AI} + w_e \cdot E \right)$$

Trong đó tổng trọng số được chuẩn hóa:
$$w_s + w_p + w_a + w_e = 0.35 + 0.10 + 0.30 + 0.25 = 1.00$$

1. **$S_{eff}$ (Effective Static Severity) $\in [0.0, 1.0]$:**
   $$S_{eff} = \min(1.0, \max(0.0, S_{base} + \Delta_{CWE}))$$
   - $S_{base}$: Quy đổi severity tĩnh của OpenGrep (Critical: 1.0, Error/High: 0.85, Warning/Medium: 0.55, Low: 0.25, Info: 0.10).
   - $\Delta_{CWE}$: Hệ số điều chỉnh tác động nội tại theo CWE (ví dụ RCE CWE-78/502: +0.10, SQLi CWE-89: +0.08, Path Traversal CWE-22: +0.05).

2. **$P$ (Rule Precision) $\in [0.0, 1.0]$:**
   - Đánh giá chất lượng của Rule: `VERY-HIGH` (1.0), `HIGH` (0.85), `MEDIUM` (0.60), `LOW` (0.40), `UNKNOWN` (0.50).

3. **$C_{AI}$ (AI Verification Confidence) $\in [0.0, 1.0]$:**
   - Độ tin cậy định lượng từ mô hình LLM fine-tuned khi phân loại vai trò hàm mục tiêu (`sink`, `source`, `taint-propagator`, `none`).

4. **$E$ (Exploitability / Dataflow Reachability) $\in [0.0, 1.0]$:**
   - Có vết Taint Source -> Intermediate -> Sink đầy đủ: $E = 1.00$.
   - Có Source và Sink nhưng thiếu bước trung gian: $E = 0.85$.
   - Chỉ có Source hoặc Sink: $E = 0.60$.
   - Chỉ pattern matching tĩnh: $E = 0.30$.

### Tầng 2: Hệ số phạt Báo động giả (False Positive Penalty)
$$FinalScore = \text{round}\left( RawScore \times \gamma_{FP}, 1 \right)$$

Hệ số phạt $\gamma_{FP}$ được quyết định dựa trên phán quyết của mô hình AI:
$$\gamma_{FP} = \begin{cases} 
1.00 & \text{nếu AI xác nhận là TRUE\_POSITIVE} \\
0.75 & \text{nếu AI phân loại là SUSPICIOUS\_UNVERIFIED} \\
0.15 & \text{nếu AI xác nhận là FALSE\_POSITIVE / BENIGN (Mã an toàn)}
\end{cases}$$

> **Ý nghĩa khoa học:** Khi mô hình AI xác định một cảnh báo là False Positive (hàm vô hại `none`), hệ số phạt $0.15$ sẽ ép điểm số xuống dưới $20.0$, lập tức đẩy cảnh báo đó xuống nhóm đáy (Low/Benign) và loại bỏ hoàn toàn tình trạng Alert Fatigue cho lập trình viên.

---

## 3. PHÂN BỔ NHÓM RỦI RO (RISK BANDS)

| Dải điểm ($FinalScore$) | Nhóm rủi ro | Hành động khuyến nghị trong quy trình DevSecOps |
|---|---|---|
| **85.0 - 100.0** | **CRITICAL** | Chặn pipeline CI/CD (Build Gate Fail); yêu cầu vá khẩn cấp trước khi release. |
| **70.0 - 84.9** | **HIGH** | Cảnh báo mức cao; bắt buộc sửa chữa trong sprint hiện tại. |
| **40.0 - 69.9** | **MEDIUM** | Xem xét trong đợt kiểm toán định kỳ; rủi ro phụ thuộc vào ngữ cảnh triển khai. |
| **20.0 - 39.9** | **LOW** | Ghi nhận thông tin; rủi ro thấp hoặc thiếu luồng tấn công khả dĩ. |
| **0.0 - 19.9** | **BENIGN / FP** | Đã được AI xác nhận là báo động giả; tự động gắn nhãn loại trừ khỏi danh sách cần xử lý. |

---

## 4. KẾT QUẢ KIỂM ĐỊNH THỰC NGHIỆM (UNIT TEST SUITE)

Mô hình đã vượt qua 100% các ca kiểm thử trong `tests/unit/test_sast_scoring_engine.py`:
- **Tính an toàn biên (Boundary Safety):** Điểm luôn thỏa mãn $0.0 \le FinalScore \le 100.0$ với mọi tổ hợp đầu vào.
- **Tính đơn điệu (Monotonicity):** Duy trì trật tự $CRITICAL > HIGH > MEDIUM > LOW$.
- **Khả năng hạ bậc FP (Demotion Power):** Một lỗi ban đầu xếp Critical (RawScore ~90) bị ép xuống còn **13.5** (BENIGN/FP) khi AI chỉ ra là False Positive.
- **Khả năng tự phục hồi (Robustness):** Chạy trơn tru và trả về điểm trung tính an toàn ngay cả khi dữ liệu khuyết thiếu metadata/CWE/dataflow.
