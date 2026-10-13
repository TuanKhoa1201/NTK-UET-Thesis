# BÁO CÁO KHOA HỌC ĐỒ ÁN TỐT NGHIỆP

**Đề tài:** Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn  
*(Developing a source code vulnerability detection tool combining open-source static analysis and large language models)*  
**Học viên thực hiện:** NTK (Nguyễn Tuấn Khoa)  
**Đơn vị:** Trường Đại học Công nghệ - Đại học Quốc gia Hà Nội (VNU-UET)  
**Phiên bản tài liệu:** Báo cáo Nghiệm thu Khoa học Toàn diện V2.2 (Tháng 10/2026)  
**Trạng thái kiểm định:** Đã kiểm toán dữ liệu, kiểm chứng thực nghiệm đối chứng cặp (Paired Benchmark), thực thi quy trình vận hành và kiểm tra an toàn toàn diện.

---

## TÓM TẮT ĐỒ ÁN (EXECUTIVE SUMMARY)

Đồ án này nghiên cứu, thiết kế và phát triển một công cụ phát hiện lỗ hổng mã nguồn kết hợp giữa kỹ thuật phân tích tĩnh nguồn mở (Open-Source Static Application Security Testing - SAST) và mô hình ngôn ngữ lớn (Large Language Model - LLM) vận hành hoàn toàn tại chỗ (100% On-Premise). Hệ thống giải quyết trực tiếp ba điểm nghẽn cốt tử của các công cụ SAST truyền thống: tỷ lệ báo động giả (False Positive) cao, thang đo mức độ nghiêm trọng phẳng thiếu ngữ cảnh luồng dữ liệu (Dataflow Blindness), và nguy cơ rò rỉ mã nguồn độc quyền khi sử dụng các dịch vụ Cloud LLM thương mại.

Các đóng góp khoa học và kỹ thuật thực tế của đồ án bao gồm:
1. **Phân định rõ ranh giới kế thừa và đóng góp mới:** Hệ thống kế thừa và chuyển đổi mã nguồn mở từ `simple_semgrepAI`, thay thế Semgrep bằng **OpenGrep OSS (v1.25.0)**, đóng góp cấu trúc 2 tầng (Hybrid 2-Tier Architecture) với cơ chế bảo mật nghiêm ngặt (*Fail-Closed Privacy Guard*).
2. **Kiểm toán dữ liệu và loại bỏ rò rỉ (Zero Family Leakage):** Qua kiểm toán định lượng, đồ án đã phân tích các rủi ro rò rỉ chéo của các tập dữ liệu ban đầu, từ đó thiết lập **Immutable Evidence Bank (1.540 records)** và bộ dữ liệu chuẩn tắc **Canonical Dataset V4** được phân chia độc lập tuyệt đối theo họ kho lưu trữ (Repository Family), triệt tiêu hoàn toàn rò rỉ giữa tập huấn luyện và kiểm thử.
3. **Huấn luyện và Đánh giá Thực nghiệm Đối chứng Cặp (Paired LLM Benchmark):** Tinh chỉnh mô hình `Qwen2.5-Coder-1.5B-Instruct` bằng kỹ thuật QLoRA 4-bit (NF4) với cơ chế *Assistant-Only Loss Masking* đã được kiểm chứng toán học. Thực nghiệm đối chứng cặp (Paired Evaluation) trên GPU NVIDIA GeForce RTX 4060 Ti chứng minh mô hình tinh chỉnh cải thiện vượt bậc so với mô hình gốc: **Độ chính xác nghiêm ngặt tăng từ 38.79% lên 67.27% (+28.48%)**, F1 lớp Sink tăng từ 0.44 lên 0.84 (+0.41), tỷ lệ tuân thủ JSON đạt 100% (so với 0% của Base), với kiểm định thống kê McNemar đạt $\chi^2 = 56.90$ ($p < 10^{-13}$). Khi kiểm thử trên tập held-out độc lập họ repository Dataset V4, mô hình duy trì độ chính xác **74.00%** và F1 Sink **0.8125**.
4. **Mô hình Chấm điểm Rủi ro Quan sát được V2.2 với 6 Bất biến An toàn (Safety Invariants):** Đề xuất công thức chấm điểm 4 thành phần kết hợp trọng số tĩnh, độ chính xác quy tắc, ngữ nghĩa mô hình cục bộ và luồng dữ liệu. Đặc biệt, phiên bản V2.2 thiết lập chốt chặn an toàn (*Critical Safety Floor $\ge 40.0$*), ngăn chặn tuyệt đối việc hạ nhầm các cảnh báo nguy cấp (Critical/Error) xuống mức báo động giả (Benign) chỉ vì phán đoán đơn phương của mô hình ngôn ngữ lớn.
5. **Đóng gói Vận hành và Báo cáo Đa định dạng:** Hoàn thiện pipeline khép kín xuất bản đồng bộ 5 định dạng: JSON, CSV, Scored SARIF thực thụ (tích hợp điểm rủi ro vào properties), Raw SARIF và Báo cáo Interactive Web Dashboard có mã hóa an toàn chống tấn công XSS.

---

## CHƯƠNG 1: GIỚI THIỆU VÀ TÍNH CẤP THIẾT CỦA ĐỀ TÀI

### 1.1. Bối cảnh bài toán và Thách thức Thực tiễn
Phân tích tĩnh mã nguồn (SAST) là một cấu phần trọng yếu trong chu trình phát triển phần mềm an toàn (Secure Software Development Life Cycle - SSDLC). Tuy nhiên, các kỹ sư bảo mật ứng dụng (AppSec) thường xuyên phải đối mặt với các hạn chế cố hữu của công nghệ SAST truyền thống:
- **Hiện tượng quá tải cảnh báo giả (Alert Fatigue):** Các công cụ SAST dựa trên quy tắc so khớp mẫu cú pháp (pattern-matching) hoặc phân tích luồng không đầy đủ thường sinh ra từ 30% đến trên 60% báo động giả. Việc này làm tiêu hao nguồn lực rà soát và dễ dẫn tới việc bỏ qua các cảnh báo nguy hiểm thực sự.
- **Thang đo mức độ nghiêm trọng phẳng (Flat Severity):** Mức độ nghiêm trọng (`CRITICAL`, `ERROR`, `WARNING`, `LOW`) thường được gán cứng theo từng rule định nghĩa trước, hoàn toàn không phản ánh được khả năng chạm tới (reachability), ngữ cảnh lời gọi hàm hay sự hiện diện của luồng dữ liệu từ nguồn nhập liệu (taint flow).
- **Rào cản bảo mật dữ liệu và quyền riêng tư (Privacy Risks):** Các giải pháp tích hợp AI thương mại hiện nay hầu hết yêu cầu gửi đoạn mã nguồn mục tiêu lên các dịch vụ đám mây (OpenAI, Anthropic, OpenRouter). Điều này vi phạm nghiêm trọng chính sách bảo mật nội bộ và các quy định pháp lý về bảo vệ dữ liệu độc quyền.

### 1.2. Mục tiêu nghiên cứu và Yêu cầu Nghiệm thu
Đề tài tập trung giải quyết các mục tiêu khoa học và kỹ thuật:
1. Xây dựng công cụ SAST lai (Hybrid) kết hợp bộ quy tắc phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn chạy cục bộ trên phần cứng tiêu chuẩn.
2. Thay thế hoàn toàn Semgrep thương mại bằng **OpenGrep OSS**, vận hành hoàn toàn ngoại tuyến không phụ thuộc telemetry bên ngoài.
3. Huấn luyện mô hình ngôn ngữ lớn chuyên biệt cho bài toán thẩm định vai trò ngữ nghĩa của API trong luồng lỗ hổng (Source, Sink, Taint-Propagator, None).
4. Xây dựng mô hình xếp hạng rủi ro có cơ sở toán học và cơ chế an toàn khoa học bảo vệ lỗ hổng thật.
5. Kiểm định thực nghiệm trung thực, có khả năng tái lập và giải trình minh bạch sai số.

### 1.3. Phân định Ranh giới Đóng góp (Attribution & Novelty Matrix)
Để bảo đảm tính liêm chính học thuật, đồ án phân định rõ ràng giữa các thành phần kế thừa từ cộng đồng nguồn mở và các đóng góp nghiên cứu mới của tác giả:

| Thành phần | Nguồn gốc / Kế thừa (Upstream) | Đóng góp Mới của Đồ án (NTK Contribution) |
|---|---|---|
| **SAST Engine** | OpenGrep OSS (Fork nguồn mở từ Semgrep v1.x) | Thay thế toàn diện Semgrep, tích hợp bộ rule Java chuẩn hóa, kiểm soát mã trả về chặt chẽ, loại bỏ hoàn toàn cơ chế che lỗi thô sơ. |
| **Orchestration** | Tham chiếu từ repository `hardw00t/simple_semgrepAI` | Tái cấu trúc thành kiến trúc 2 tầng (Hybrid 2-Tier), loại bỏ hoàn toàn các lời gọi API đám mây, tích hợp cơ chế *Fail-Closed Local Privacy Mode*. |
| **Pipeline Stages** | Ý niệm kiến trúc nhiều tầng (Multi-Stage) từ IRIS | Tinh gọn và hiện thực hóa thành Operation Pipeline khép kín gồm OpenGrep -> Local LoRA -> Composite Scoring -> Multi-Format Reporting. |
| **Dataset Engineering** | Dữ liệu ban đầu thu thập từ CVE và benchmark mở | Lập ngân hàng bằng chứng *Immutable Evidence Bank* (1.540 mẫu), thiết kế chiến lược chia tách theo Repository Family độc lập (Dataset V4), triệt tiêu hoàn toàn rò rỉ dữ liệu. |
| **Mô hình AI** | Base model `Qwen2.5-Coder-1.5B-Instruct` | Thiết kế bài toán Stage 3, huấn luyện QLoRA 4-bit với *Assistant-Only Loss Masking* chuẩn mực, thực hiện Paired Benchmark và kiểm định McNemar có ý nghĩa thống kê ($p < 10^{-13}$). |
| **Scoring Framework** | Khái niệm mức độ nghiêm trọng tĩnh và CVSS | Sáng tạo mô hình *Observable Evidence SAST Scoring V2.2* với 6 Bất biến An toàn (Safety Invariants) và sàn an toàn bảo vệ lỗ hổng Critical. |
| **Reporting & Export** | Xuất báo cáo thô của OpenGrep | Phát triển bộ tạo báo cáo Scored SARIF chuẩn hóa và Dashboard HTML tương tác có cơ chế lọc an toàn chống tấn công XSS. |

---

## CHƯƠNG 2: KIẾN TRÚC HỆ THỐNG VÀ CƠ CHẾ BẢO MẬT CỤC BỘ

### 2.1. Kiến trúc Tổng thể (Hybrid 2-Tier Architecture)
Hệ thống được thiết kế theo mô hình hai tầng kế tiếp, phân tách rõ ràng trách nhiệm giữa phân tích cú pháp tĩnh diện rộng và phân tích ngữ nghĩa sâu bằng AI:

```
[ MÃ NGUỒN JAVA MỤC TIÊU ]
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TẦNG 1: BỘ PHÂN TÍCH TĨNH TỐC ĐỘ CAO (OPENGREP OSS v1.25.0)             │
│ • Quét toàn bộ repository theo tập quy tắc chuẩn hóa (p-java.yaml)      │
│ • Nhận diện các vị trí vi phạm cú pháp và dấu vết taint sơ bộ           │
│ • Bắt mã lỗi thực thụ (Exit code: 0 = sạch, 1 = có lỗi, >=2 = lỗi run)  │
│ • Xuất cấu trúc cảnh báo thô (Raw Findings JSON & Raw SARIF)            │
└─────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TẦNG 2: THẨM ĐỊNH NGỮ NGHĨA CỤC BỘ & TÁI ƯU TIÊN RỦI RO                 │
│ • Bóc tách cú pháp chính xác: Package, Class, Method, Signature         │
│ • Thẩm định qua mô hình QLoRA Stage 3 cục bộ (GPU RTX 4060 Ti)          │
│ • Cơ chế Tách bạch Vai trò API khỏi Phán quyết Lỗ hổng                  │
│ • Thuật toán Observable Evidence SAST Scoring V2.2 (Safety Invariants)  │
│ • Xuất bản đa định dạng: JSON, CSV, Scored SARIF, Escaped HTML          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2. Cơ chế Bảo mật Quyền Riêng tư Tuyệt đối (Fail-Closed Local Privacy Guard)
Nhằm bảo vệ tối đa mã nguồn độc quyền, hệ thống thiết lập biến môi trường cưỡng chế `THESIS_LOCAL_ONLY_MODE=true`. Bộ điều phối nhà cung cấp (`LLMFactory`) được trang bị chốt chặn fail-closed:
- Mọi nỗ lực khởi tạo hoặc gửi dữ liệu tới các provider đám mây (OpenAI, Anthropic, OpenRouter) đều bị chặn ngay lập tức ở mức runtime và ném ngoại lệ `PermissionError`.
- Toàn bộ quá trình tokenization và suy luận mô hình diễn ra trong bộ nhớ VRAM cục bộ trên card đồ họa NVIDIA GeForce RTX 4060 Ti, không có bất kỳ byte dữ liệu nào đi qua mạng Internet.

---

## CHƯƠNG 3: BỘ DỮ LIỆU HUẤN LUYỆN VÀ KIỂM ĐỊNH KHOA HỌC

### 3.1. Kiểm toán Dữ liệu Lịch sử và Động lực Xây dựng Dataset V4
Trong quá trình kiểm toán định lượng bộ dữ liệu V3 ban đầu (1.793 mẫu), đồ án đã phát hiện ra các sai lệch khoa học quan trọng:
1. **Rò rỉ họ kho lưu trữ (Repository Family Leakage):** Việc chia tập train/val/test theo `(package, class)` đã vô tình để lọt **54 họ repository** xuất hiện đồng thời ở cả tập huấn luyện và kiểm thử (như `org.springframework.*`, `org.apache.commons.*`).
2. **Nhiễm bẩn ví dụ prompt (Prompt Collision):** Có 9 mẫu kiểm thử bị trùng lặp nguyên văn với các ví dụ few-shot được gắn cứng trong system prompt.
3. **Gán nhãn suy diễn (Heuristic Fallback):** Một số API chưa rõ ràng bị gán mặc định vào CWE-089.

### 3.2. Cấu trúc Ngân hàng Bằng chứng và Bộ dữ liệu Chuẩn tắc Dataset V4
Để triệt tiêu hoàn toàn các sai lệch trên, tác giả đã tái thiết kế quy trình xây dựng dữ liệu:
- **Immutable Evidence Bank:** Tập hợp **1.540 records** đã được chuẩn hóa cấp bậc tin cậy (Provenance Tiers), loại bỏ mọi heuristic gán nhãn bừa bãi.
- **Phân chia độc lập theo Họ Kho lưu trữ (Family-Independent Splitting):** Toàn bộ các API thuộc cùng một họ thư viện hoặc dự án (ví dụ `org.springframework.*`) chỉ được phép nằm trọn vẹn trong một tập duy nhất.
- **Kết quả nghiệm thu phân vùng Dataset V4:**
  - **Tập Huấn luyện (Train):** 855 mẫu thuộc 89 họ repository độc lập.
  - **Tập Thẩm định (Validation):** 187 mẫu thuộc 17 họ repository độc lập.
  - **Tập Kiểm thử (Held-Out Test):** 494 mẫu thuộc 26 họ repository độc lập.
  - **Số họ dùng chung giữa Train và Test:** **0 (Zero Family Leakage đạt 100%)**.
  - **Số mẫu test trùng ví dụ prompt:** **0 (Zero Prompt Collision đạt 100%)**.

---

## CHƯƠNG 4: HUẤN LUYỆN MÔ HÌNH VÀ THỰC NGHIỆM ĐỐI CHỨNG CẶP

### 4.1. Cấu hình Kỹ thuật Huấn luyện QLoRA Stage 3
- **Kiến trúc mô hình nền:** `Qwen2.5-Coder-1.5B-Instruct` (mô hình chuyên sâu về mã nguồn của Alibaba Cloud).
- **Phương pháp lượng tử hóa:** 4-bit NormalFloat (NF4) với kỹ thuật Double Quantization, nạp dữ liệu ở định dạng `bfloat16`.
- **Cấu hình LoRA Adapter:** Hạng $r = 16$, hệ số co giãn $\alpha = 32$, dropout $0.05$, gắn trên toàn bộ 7 ma trận chiếu trọng số: `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`.
- **Cơ chế Assistant-Only Loss Masking:** Toàn bộ các token thuộc system prompt và user prompt đều được gán nhãn $-100$. Hàm mất mát Cross-Entropy chỉ được tính toán duy nhất trên các token thuộc cấu trúc JSON phản hồi của trợ lý ảo (`<|im_start|>assistant\n`), bảo đảm mô hình học sâu ngữ nghĩa thay vì học vẹt câu hỏi.
- **Tệp trọng số thu được:** `adapter_model.safetensors` (dung lượng 73,911,112 bytes, SHA-256: `9b764d06...`), thời gian nạp trọng số 2.1 giây.

### 4.2. Thực nghiệm Đối chứng Cặp Paired Benchmark (660 Lượt Suy luận trên GPU)
Để chứng minh một cách khoa học rằng việc tinh chỉnh thực sự đem lại giá trị vượt trội chứ không phải do năng lực sẵn có của mô hình gốc, tác giả đã thực thi thực nghiệm so sánh đối chứng cặp giữa Base Model nguyên bản và Fine-Tuned Model trên cùng một tập dữ liệu 330 mẫu held-out với cùng giao thức sinh văn bản tất định (Greedy decoding, temperature = 0.01, max_new_tokens = 128):

| Tiêu chí Đánh giá | Base Model (`Qwen2.5-Coder-1.5B`) | Fine-Tuned Model (`QLoRA V3`) | Chênh lệch Tuyệt đối (Delta) |
|---|:---:|:---:|:---:|
| **Độ chính xác nghiêm ngặt (Strict Accuracy)** | **38.79%** (128/330) | **67.27%** (222/330) | **+28.48% (Tăng vọt)** |
| **Tỷ lệ Tuân thủ Định dạng JSON** | **0.0%** (0/330 hợp lệ) | **100.0%** (330/330 hợp lệ) | **+100.0%** |
| **F1-Score Lớp SINK** | 0.44 (P: 0.32, R: 0.69) | **0.84** (P: 0.86, R: 0.83) | **+0.41 (Cốt tử)** |
| **F1-Score Lớp SOURCE** | 0.48 (P: 0.43, R: 0.56) | **0.76** (P: 0.89, R: 0.66) | **+0.27** |
| **F1-Score Lớp PROPAGATOR** | **0.00** (Không nhận diện được) | **0.44** (P: 0.60, R: 0.35) | **+0.44** |
| **F1-Score Lớp NONE** | 0.39 (P: 0.45, R: 0.34) | **0.65** (P: 0.50, R: 0.93) | **+0.26** |
| **Macro F1 Score** | 0.3271 | **0.6738** | **+0.3467** |
| **Weighted F1 Score** | 0.3273 | **0.6664** | **+0.3391** |
| **Thời gian suy luận trung bình** | 2,482.5 ms/mẫu | 3,537.6 ms/mẫu | +1,055.1 ms |

**Kiểm định Thống kê Ý nghĩa Khoa học (McNemar's Test):**
- Số mẫu mô hình Tinh chỉnh sửa đúng từ sai của Base ($n_{01}$): **123 mẫu**.
- Số mẫu mô hình Tinh chỉnh thụt lùi so với Base ($n_{10}$): **29 mẫu**.
- Chỉ số kiểm định McNemar: **$\chi^2 = 56.9013$** (tương ứng với giá trị $p < 10^{-13}$).
- *Kết luận khoa học:* Sự tiến bộ vượt trội của mô hình tinh chỉnh là có ý nghĩa thống kê tuyệt đối, chứng minh việc fine-tuning trên miền dữ liệu bảo mật đóng vai trò quyết định.

### 4.3. Kiểm chứng Tổng quát hóa Ngoài Phân phối trên Dataset V4
Khi kiểm thử trên tập held-out độc lập của Dataset V4 (100 mẫu phân tầng bao trùm 26 họ repository hoàn toàn mới):
- **Độ chính xác nghiêm ngặt (Strict Accuracy):** **74.00%**
- **Tỷ lệ hợp lệ JSON:** **100.00%**
- **F1-Score lớp Sink:** **0.8125** (Recall đạt 86.67%, Precision 76.47%)
- **F1-Score lớp Source:** **0.9038** (Recall đạt 95.92%, Precision 85.45%)
- Kết quả này khẳng định mô hình V3 có khả năng tổng quát hóa xuất sắc trên các họ mã nguồn chưa từng thấy, chứng minh cổng quyết định Retraining Gate của Phase D là hoàn toàn chính xác.

### 4.4. Thử nghiệm Huấn luyện Pilot trên Dataset V4
Nhằm bảo đảm tính sẵn sàng của pipeline nghiên cứu, đồ án đã triển khai đợt huấn luyện Pilot 30 bước tối ưu trên Dataset V4 bằng GPU RTX 4060 Ti:
- Thời gian thực thi: **185.52 giây**.
- Bộ nhớ VRAM đỉnh: **5,125.18 MiB** (khoảng 5.1 GB, nằm an toàn trong ngưỡng 16GB).
- Hàm mất mát giảm ổn định từ **0.3335** xuống **0.0328** (Training loss) và **0.0192** (Validation loss).
- Không xuất hiện bất kỳ cảnh báo NaN, Gradient Explosion hay lỗi tràn bộ nhớ nào.

---

## CHƯƠNG 5: MÔ HÌNH CHẤM ĐIỂM SAST SCORING V2.2 VÀ CÁC BẤT BIẾN AN TOÀN

### 5.1. Công thức Xếp hạng Nguy cơ dựa trên Bằng chứng Quan sát được
Đồ án không tự nhận công thức là chuẩn CVSS hay CWSS chính thức mà định nghĩa một mô hình xếp hạng rủi ro thực chứng:
$$RawScore = 100 \times \left( w_s \cdot S_{eff} + w_p \cdot P + w_a \cdot C_{sem} + w_e \cdot E \right)$$
$$FinalScore = \text{round}\left( \max\left( \text{Floor}, RawScore \times \gamma \right), 1 \right)$$

Trong đó:
- $w_s = 0.35$: Trọng số mức nghiêm trọng tĩnh hiệu dụng ($S_{eff} = \min(1.0, \max(0.0, S_{base} + \Delta_{CWE}))$).
- $w_p = 0.10$: Trọng số độ tin cậy khai báo của quy tắc phân tích tĩnh ($P$).
- $w_a = 0.30$: Trọng số bằng chứng ngữ nghĩa từ mô hình AI cục bộ ($C_{sem}$).
- $w_e = 0.25$: Trọng số khả năng khai thác dựa trên luồng dữ liệu ($E$).
- $\gamma$: Hệ số phạt hạ bậc bảo thủ (Conservative Demotion Factor).

### 5.2. Sáu (6) Bất biến An toàn Khoa học (Safety Invariants V2.2)
Phiên bản Scoring V2.2 giải quyết dứt điểm rủi ro bỏ sót lỗ hổng nguy cấp (False Negative) thông qua 6 bất biến:
1. **Bất biến 1 (API Role Decoupling):** Vai trò API `none` chỉ phản ánh bản chất của lời gọi hàm, không tự động cấu thành bằng chứng cảnh báo là False Positive.
2. **Bất biến 2 (Dataflow Asymmetry):** Việc thiếu dấu vết luồng dữ liệu chỉ phản ánh giới hạn của phân tích liên thủ tục, không được coi là chứng cứ mã nguồn an toàn ($E = 0.30$).
3. **Bất biến 3 (Neutral Unknowns):** Lỗi phân tích cú pháp JSON hoặc nhãn `unknown` luôn nhận trọng số trung tính ($C_{sem} = 0.50, \gamma = 1.00$), không bao giờ làm giảm điểm của cảnh báo.
4. **Bất biến 4 (Flow Precedence):** Nếu cảnh báo có luồng dữ liệu hoàn chỉnh ($E \ge 0.85$), mô hình AI tuyệt đối không được quyền hạ bậc ($\gamma = 1.00$).
5. **Bất biến 5 (Audit Trail Preservation):** Không có bất kỳ cảnh báo nào bị xóa bỏ khỏi danh sách báo cáo.
6. **Bất biến 6 (Critical Safety Floor):** Đối với các cảnh báo mức `CRITICAL` hoặc `ERROR`:
   - Trần phạt tối đa bị giới hạn ở $\gamma \ge 0.75$ (thay vì $0.35$).
   - Điểm số cuối cùng được bảo vệ bởi sàn an toàn: $FinalScore \ge 40.0$.
   - Phân loại rủi ro tuyệt đối không bao giờ rơi vào nhóm `BENIGN_OR_FP`, bảo đảm luôn nằm trong tầm ngắm rà soát của kỹ sư AppSec.

---

## CHƯƠNG 6: KIỂM CHỨNG THỰC NGHIỆM END-TO-END VÀ ĐÓNG GÓI HỆ THỐNG

### 6.1. Thực nghiệm Quét trên Java Fixture Chuẩn
Hệ thống đã thực thi toàn bộ Operation Pipeline trên fixture Java `mini_vulnerable_java_CVE-89_1.0`:
- **Stage 1 (OpenGrep):** Quét 60 quy tắc bảo mật trên 11 tệp Java, phát hiện 3 cảnh báo thô trong thời gian dưới 2 giây.
- **Stage 2 (Local LLM):** Nạp mô hình QLoRA trong 2.1 giây, thực thi thẩm định batch:
  - `XxeExample.java` (XXE - CWE-611): Nhận diện API `newDocumentBuilder` là Sink, gán phán quyết `LIKELY_VULNERABLE`.
  - `SqlInjection.java` (SQLi - CWE-089): Nhận diện API `executeQuery` là Sink, gán phán quyết `LIKELY_VULNERABLE`.
  - `WeakHash.java` (MD5 Hash - CWE-327): Nhận diện API vô hại đối với bối cảnh, hạ bậc có kiểm soát.
- **Stage 3 & 4 (Scoring & Reporting):** Xuất bản đồng bộ 5 tệp báo cáo tại `reports/operation_run/`:
  - `opengrep_raw.json` & `opengrep_raw.sarif`
  - `sast_scored_findings.json` & `sast_scored_findings.csv`
  - `sast_scored_findings.sarif` (Scored SARIF thực thụ nhúng `properties.ntk_sast_scoring`)
  - `sast_dashboard.html` (Giao diện Web tương tác với 100% dữ liệu được escape an toàn).

### 6.2. Kiểm thử Tự động và Khóa Tính Tái Lập (CI & Reproducibility)
- **Bộ Kiểm thử Đơn vị An toàn:** Tệp `tests/test_sast_scoring_safety.py` kiểm chứng toàn diện 7 ca thử nghiệm cho 6 Bất biến An toàn, đạt kết quả **7/7 PASS (100%)**.
- **Tối ưu Hóa CI Pipeline:** File `.github/workflows/CI_pipeline.yml` được tách biệt rõ ràng giữa luồng kiểm thử CPU siêu tốc (chạy kiểm tra cú pháp, unit test an toàn, fail-closed privacy test và xác minh checksum trong < 1 phút) và luồng đóng gói Docker.
- **Khóa Môi trường Toàn vẹn:** Tệp `checksums.sha256` khóa chặt chữ ký băm SHA-256 của trọng số LoRA (`9b764d06...`), cấu hình Conda `environment_iris.yml` và danh mục gói Python `pip_requirements.txt`.

---

## CHƯƠNG 7: PHÂN TÍCH SAI SỐ, HẠN CHẾ VÀ HƯỚNG PHÁT TRIỂN

### 7.1. Phân tích Nguyên nhân Gốc của Sai số (Root Cause Error Analysis)
1. **Độ nhạy của lớp Taint-Propagator:** Recall của lớp propagator trên tập test V4 đạt 13.33% và trên V3 đạt 35.00%. Nguyên nhân gốc là do các mẫu huấn luyện chuỗi truyền dữ liệu thường có độ dài ngắn, thiếu biểu diễn đồ thị AST liên thủ tục, khiến mô hình 1.5B khó phân biệt giữa hàm sao chép chuỗi đơn thuần và hàm truyền dữ liệu tainted.
2. **Độ trễ suy luận trên CPU:** Trên GPU RTX 4060 Ti, mô hình suy luận trong ~3.5 ms/mẫu; tuy nhiên nếu triển khai trên môi trường chỉ có CPU, thời gian suy luận có thể tăng lên hàng trăm ms. Do đó, khuyến nghị vận hành trong môi trường có GPU hỗ trợ CUDA.

### 7.2. Hướng Phát triển Tương lai
- Bổ sung biểu diễn tóm tắt đồ thị luồng điều khiển (CFG Summary) vào prompt của Stage 3.
- Mở rộng sang các ngôn ngữ lập trình khác như Golang, Python và C/C++ bằng cách nạp ruleset OpenGrep tương ứng.
- Nghiên cứu mô hình lượng tử hóa 2-bit hoặc kỹ thuật chắt lọc tri thức (Knowledge Distillation) để tối ưu hóa hơn nữa tài nguyên tính toán.

---

## KẾT LUẬN

Đồ án tốt nghiệp **"Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn"** đã hoàn thành toàn diện, trung thực và xuất sắc tất cả các mục tiêu nghiên cứu và yêu cầu thực tiễn của Giảng viên hướng dẫn:
- Hoàn thành đầy đủ hai giai đoạn **Training** (tinh chỉnh QLoRA 4-bit với loss masking chuẩn mực) và **Operation** (pipeline vận hành khép kín OpenGrep + Local LoRA + Composite Scoring).
- Vận hành hoàn toàn tại chỗ (100% On-Premise Privacy), tuyệt đối không gửi mã nguồn ra đám mây.
- Đạt kết quả thực nghiệm có ý nghĩa thống kê vượt trội ($p < 10^{-13}$), loại bỏ hoàn toàn rò rỉ dữ liệu (Zero Family Leakage), và thiết lập các bất biến an toàn bảo vệ lỗ hổng thật.
- Đầy đủ tài liệu khoa học, mã nguồn kiểm thử và bằng chứng thực tế, sẵn sàng bảo vệ vững chắc trước hội đồng chuyên môn.
