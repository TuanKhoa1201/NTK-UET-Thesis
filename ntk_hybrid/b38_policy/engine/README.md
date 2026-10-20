# NTK Batch 37A — Fresh Java ZIP → real local hybrid CWE-89 (CLI gate)

**Đích:** Bước 37A đầu tiên nối **một dự án Java mới** (không dùng kết quả replay B34/B35) tới `OpenGrep → compiler API candidates → native IRIS Stage 3 + local LoRA → CodeQL source-to-sink → B35 semantic guard → frozen SAST scoring V2.2 → JSON/SARIF`.

## Không nên hiểu quá phạm vi

- **Đã kiểm chứng tại môi trường xây dựng gói:** mã Python, 22 unit tests, compile một Java ZIP mới với `javac 21`, so sánh semantic guard với labels thực lưu trong B34R5. Chưa có CodeQL/OpenGrep/LoRA binary trong môi trường xây dựng để chạy toàn tuyến. `B37A_SCOPED_HYBRID_COMPLETE` chỉ được phép xuất hiện từ WSL khi chạy đủ lệnh thật.
- **Phạm vi B37A:** từ 1 tới 24 tệp `.java` **JDK-only**; không có Maven/Gradle hay dependency bên ngoài. Không thực thi mã nguồn Java, không chạy shell/build script trong ZIP, không tự cài dependency hay tải model.
- **Nguồn dữ liệu (source) CWE-89:** chỉ `java.lang.System.getenv(String)` tại các **callsite thực do CodeQL trích từ database của dự án vừa nhập**, theo **chính sách đe dọa giả định giá trị trả về là chưa tin cậy**. KHÔNG phải source mà LLM tự nhận diện, không đủ bao phủ các dự án Java tổng quát, không đồng nghĩa input khai thác từ Internet.
- **Sink:** chỉ nhãn LoRA Stage 3 đáp ứng JSON/identity/overload/sink_args và được semantic guard B35 chấp thuận (SQL text của `Statement.execute`, `executeQuery`, `Connection.prepareStatement`). Giá trị binding của `PreparedStatement.setString` không là SQL-grammar sink. Các API không có trong chính sách cần xem xét, không coi là `none` hoặc false positive.
- B37A dùng hàm native `SAPipeline.query_gpt_for_api_src_tp_sink_batched()`; **không phải** `SAPipeline.run()` end-to-end, không chạy Stage 4/posthoc, không có benchmark độc lập và chưa mở rộng CWE-22/78/79.
- OpenGrep dùng **rule demo** tìm callsite, không phải benchmark B29. Bốn cảnh báo OpenGrep ban đầu phải được giữ nguyên, kể cả khi không có flow hoặc LLM ABSTAIN.
- SAST score V2.2 là **điểm ưu tiên**, không phải xác suất vulnerability hoặc CVSS; không tự động xóa cảnh báo.
- Chưa tích hợp trực tiếp vào website B36R1. Kết quả 37A là cổng CLI trước khi làm Batch 37B Web Integration.

## Cơ chế bảo toàn và an toàn

1. SHA-pinned `B33_RESULT` (giữ nguyên checkpoint Qwen2.5-Coder-0.5B), commit `51c2aafaf2746a6246ab057752791cc397c272d4`, 16 local QL packs đã kiểm tra fingerprints.
2. Tạo Git archive snapshot **bên ngoài** `~/iris`; không ghi vào repository gốc, adapter hoặc database B34/B35.
3. ZIP mới được kiểm tra traversal, symlink, duplicate path, tỷ lệ nén, số tệp, dung lượng; chỉ giải nén `.java` vào workspace mới. `javac -proc:none` chỉ biên dịch Java thuần JDK; ứng dụng không được chạy. Chỉ dùng ZIP từ **nguồn bạn tin cậy**: JDK compiler/CodeQL trên host WSL chưa phải container sandbox chống mã nguồn độc hại.
4. OpenGrep offline có cấm IPv4/IPv6; LoRA/IRIS kế thừa cấm IPv4/IPv6 như B33/B34. CodeQL tắt telemetry và chỉ dùng QL packs local; **bản chạy tạo database CodeQL không có bằng chứng cấm mạng kernel-level tương đương** — không gắn nhãn đã xác thực sandbox toàn toolchain.
5. `queries/ApiCalls.ql` và `ArgumentSpans.ql` bỏ mọi bộ lọc package `ntk.b34`, tập trung vào `java.sql` SQL calls + `java.lang.System.getenv`, tính owner và overload từ database mới. Query compile trước khi làm DB/GPU.
6. Dữ liệu báo cáo lưu `RUN_DIR` đầy đủ; ZIP kết quả **không bao gồm file `.java` đã upload, db hoặc weights**, nhưng có thể chứa đoạn mã và tên API trong log/JSON/SARIF. Kiểm tra dữ liệu nhạy cảm trước khi gửi ZIP ra ngoài.

## Chạy lần đầu trên WSL `(iris)`

Yêu cầu còn ZIP B33 trong Downloads và `$W/.ntk_v5_lora_venv/bin/python`, CodeQL 2.25.6 và OpenGrep 1.25.0 đã được chứng minh ở B34/B36R1. **Dừng website B36R1 không bắt buộc**, CLI này dùng workspace riêng.

```bash
export NTK_IRIS_PYTHON="$(command -v python)"
W="$HOME/migration/ntk_stage3_verified_v5_work"
D="/mnt/c/Users/HP/Downloads"
# Gói phải được giải nén vào thư mục mới; chạy ./run.sh không đối số để dùng ZIP mẫu MỚI trong gói.
bash /path/to/ntk_batch37a_new_java_hybrid_20261019/run.sh
```

Dùng Java ZIP đáng tin cậy khác, ví dụ:

```bash
bash /path/to/ntk_batch37a_new_java_hybrid_20261019/run.sh \
  --project-zip /mnt/c/Users/HP/Downloads/my_jdk_only_java.zip --arm epoch_1
```

Dùng `--arm both` khi muốn chạy Epoch 1 và Epoch 2 tuần tự trên cùng dự án và cùng candidate/query pipeline.

## Trạng thái cuối

- `B37A_SCOPED_HYBRID_COMPLETE`: CodeQL mới + LoRA mới + semantic guard + scoring đã chạy, có ít nhất một đường đạt chính sách. **Với ZIP mẫu** còn yêu cầu hai ca dương và hai ca âm khớp kỳ vọng phát triển; vẫn không phải gold độc lập.
- `B37A_COMPLETED_NEEDS_REVIEW`: mọi cổng chính đã chạy nhưng không có flow đủ điều kiện/ZIP mẫu không khớp; **không ép kết luận false positive hoặc sửa expected**.
- `B37A_BLOCKED`: thất bại kỹ thuật, log và `BLOCKER` được đóng gói; các stage chưa chạy không được nói là đã đạt.

Khi chạy xong, giữ nguyên `RUN_DIR` cùng database thật, gửi `OUTPUT_ZIP`, `OUTPUT_SHA256`, phần terminal sau `===== BATCH 37A RESULT =====`. Báo cáo đầy đủ giới hạn nghiên cứu, không lấy kết quả một sample phát triển thành F1 độc lập. Nếu thành công, bước tiếp theo là **Batch 37B — nối đúng runner B37A vào job API của website**, theo cơ chế queue một GPU job mỗi lần và hiển thị rõ provenance/mức bằng chứng.
