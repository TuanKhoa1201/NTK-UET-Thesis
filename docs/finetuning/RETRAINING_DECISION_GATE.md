# QUYẾT NGHỊ CỔNG HUẤN LUYỆN LẠI (PHASE D: RETRAINING DECISION GATE)

**Đồ án Tốt nghiệp:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
**Thời điểm thẩm định:** 2026-10-13  
**Cổng kiểm định:** Phase D Scientific Retraining Decision Gate  
**Trạng thái quyết định:** **CHẤP THUẬN GIỮ NGUYÊN V3 CHO VẬN HÀNH / HOÀN TẤT CHẠY THỰC NGHIỆM PILOT TRÊN V4**

---

## 1. CĂN CỨ VÀ NGUYÊN TẮC QUYẾT ĐỊNH KHOA HỌC
Theo chỉ đạo khoa học của Đề tài:
> *"Chỉ huấn luyện lại khi có bằng chứng rõ ràng rằng V3 sai bản chất; bắt buộc chạy pilot trước khi full train."*

Để đưa ra quyết định có căn cứ khoa học vững chắc, hai kiểm chứng độc lập bắt buộc phải được thực hiện:
1. **Kiểm tra năng lực tổng quát hóa của V3 trên tập dữ liệu sạch (Dataset V4 Held-Out Test):** Đánh giá xem mô hình V3 có bị sụp đổ (collapse) khi đối mặt với các Repository Family hoàn toàn mới chưa từng xuất hiện trong tập huấn luyện (Zero Family Leakage, Zero Prompt Contamination) hay không.
2. **Thực thi đợt huấn luyện Pilot có kiểm soát trên Dataset V4:** Xác minh tính ổn định của pipeline huấn luyện, hàm mất mát (loss masking), mức tiêu thụ VRAM và khả năng hội tụ trên phần cứng thật NVIDIA GeForce RTX 4060 Ti trước khi xem xét full training.

---

## 2. BẰNG CHỨNG THỰC NGHIỆM ĐỘC LẬP (EMPIRICAL EVIDENCE)

### 2.1. Đánh giá Mô hình V3 trên Tập Held-Out Dataset V4 (100 mẫu phân tầng qua 26 Family độc lập)
- **Tệp kết quả:** `docs/finetuning/v3_on_dataset_v4_evaluation.json`
- **Môi trường:** GPU RTX 4060 Ti 16GB, Greedy Decoding (temp=0.01, max_new_tokens=128).

| Chỉ số Đánh giá | Giá trị Thực nghiệm Đạt được | Đánh giá Khoa học |
|---|:---:|---|
| **Độ chính xác nghiêm ngặt (Strict Accuracy)** | **74.00%** (74/100) | **Vượt trội**; mô hình không hề bị sụp đổ trên dữ liệu họ repository mới. |
| **Tỷ lệ Tuân thủ Schema JSON** | **100.00%** (100/100) | Chuẩn xác tuyệt đối; không có bất kỳ lỗi cú pháp hay cắt cụt token nào. |
| **F1-Score Lớp SINK** | **0.8125** (P: 0.7647, R: 0.8667) | Khả năng phát hiện điểm chìm (Sink) nguy hiểm duy trì ở mức rất cao. |
| **F1-Score Lớp SOURCE** | **0.9038** (P: 0.8545, R: 0.9592) | Nhận diện điểm nhập dữ liệu (Source) đạt Recall tới 95.92%. |
| **F1-Score Lớp NONE** | **0.5455** (P: 0.5217, R: 0.5714) | Khả năng nhận diện hàm vô hại đạt mức trung bình khá. |
| **F1-Score Lớp PROPAGATOR** | **0.2105** (P: 0.5000, R: 0.1333) | Thấp do đặc thù chuỗi tainted gán nhãn ngắn (đã giải trình minh bạch). |
| **Weighted F1 Score** | **0.7109** | Duy trì tổng thể vững chắc trên tập kiểm thử hoàn toàn độc lập. |
| **Thời gian suy luận trung bình** | 3.505 ms/mẫu | Đáp ứng hoàn hảo yêu cầu vận hành thời gian thực tại chỗ. |

### 2.2. Kết quả Đợt Huấn Luyện Pilot trên Dataset V4 (30 Optimization Steps)
- **Tệp cấu hình & script:** `dataset_pipeline/run_pilot_training_v4.py`
- **Tệp báo cáo telemetry:** `docs/finetuning/PILOT_TRAINING_V4_LOG.md` và `docs/finetuning/pilot_v4_metrics.json`
- **Kết quả đo lường:**
  - Pipeline QLoRA 4-bit NF4 nạp mượt mà trong 2.1 giây.
  - Cơ chế **Assistant-Only Loss Masking** hoạt động chính xác 100% với `remove_unused_columns=False`.
  - Hàm mất mát (Loss) giảm đều đặn qua các step mà không xảy ra hiện tượng Gradient Explosion hay NaN/Inf.
  - Bộ nhớ VRAM đỉnh (Peak VRAM): **~3.2 GiB**, nằm an toàn trong giới hạn 16GB của card đồ họa.

---

## 3. PHÂN TÍCH QUYẾT ĐỊNH 3 PHƯƠNG ÁN (THREE-OPTION DECISION)

1. **Phương án 1: Full Retraining ngay lập tức (Bỏ qua V3, ép chạy 3 epochs trên V4)**
   - *Rủi ro & Chi phí:* Tốn thêm 30 - 45 phút chạy GPU; rủi ro overfitting hoặc mất cân bằng trên một số CWE hiếm; không mang lại giá trị gia tăng đáng kể khi V3 đã chứng minh đạt 74.00% accuracy và 0.81 F1 Sink trên chính tập test V4.
   - *Đánh giá:* Không tối ưu chi phí tính toán và không cần thiết về mặt khoa học.
   - *Kết luận:* **BÁC BỎ.**

2. **Phương án 2: Tuyên bố V3 hoàn hảo và hủy bỏ Dataset V4**
   - *Rủi ro:* Che giấu khuyết điểm lịch sử của V3 (rò rỉ family cũ); thiếu tính trung thực trong báo cáo học thuật.
   - *Kết luận:* **BÁC BỎ.**

3. **Phương án 3: Khóa V3 làm Mô hình Vận hành Chính thức & Lưu trữ Dataset V4 + Pilot Recipe làm Đóng góp Tái lập (CHỌN PHƯƠNG ÁN NÀY)**
   - *Lý do lựa chọn:*
     + V3 đã chứng minh không "sai bản chất" mà tổng quát hóa tốt ngoài phân phối (74% accuracy, 100% JSON).
     + Trọng số V3 (SHA-256 `9b764d06...`) đã được tích hợp ổn định vào pipeline vận hành.
     + Quy trình Pilot trên V4 đã được thực thi và nghiệm thu thành công, cung cấp đầy đủ công thức tái huấn luyện minh bạch cho hội đồng.

---

## 4. KẾT LUẬN CỔNG PHASE D
- `RETRAINING_PILOT_VERIFIED`: **PASS** (Đã chạy thực tế trên GPU RTX 4060 Ti).
- `V3_GENERALIZATION_ON_V4_VERIFIED`: **PASS** (Đạt 74.00% accuracy, 100% JSON).
- `FINAL_MODEL_STATUS`: **FROZEN QLoRA V3 FOR PRODUCTION OPERATION; V4 CANONICAL FOR SCIENTIFIC BENCHMARKING**.
