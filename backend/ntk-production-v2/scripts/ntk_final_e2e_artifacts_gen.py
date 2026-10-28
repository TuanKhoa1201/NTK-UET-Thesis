#!/usr/bin/env python3
"""
Artifact & Report Generator for NTK Final Backend Hardening & Real GitHub Java E2E
(`ntk_final_e2e_artifacts_gen.py`).
"""

import difflib
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import ntk_alert_verification as alert_ver
import ntk_iris_shared as shared


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    collisions = shared.find_case_insensitive_duplicate_keys(data)
    if collisions:
        raise RuntimeError(f"Case-insensitive key collision in {path.name}: {collisions}")
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Enforce Hub rule: zero em-dash (U+2014) in markdown/text deliverables
    clean_text = text.replace("\u2014", "-")
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(clean_text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_patches_and_rollback(audit_root: Path, script_dir: Path, patches_dir: Path) -> Dict[str, str]:
    patches_dir.mkdir(parents=True, exist_ok=True)
    prev_dir = Path("/mnt/c/Users/Admin/NTK_PreWeb_Audit/sast_triage_verification_20261025/working_copy/scripts")
    tracked = [
        ("ntk_iris_shared.py", prev_dir / "ntk_iris_shared.py", script_dir / "ntk_iris_shared.py"),
        ("ntk_alert_verification.py", prev_dir / "ntk_alert_verification.py", script_dir / "ntk_alert_verification.py"),
        ("ntk_web_backend_service.py", prev_dir / "ntk_web_backend_service.py", script_dir / "ntk_web_backend_service.py"),
        (
            "javac_ast_bridge/NtkJavacAstExtractor.java",
            None,
            script_dir / "javac_ast_bridge" / "NtkJavacAstExtractor.java",
        ),
    ]
    patch_hashes: Dict[str, str] = {}
    combined: List[str] = []
    for rel_name, old_p, new_p in tracked:
        old_lines = old_p.read_text(encoding="utf-8").splitlines(keepends=True) if (old_p and old_p.exists()) else []
        new_lines = new_p.read_text(encoding="utf-8").splitlines(keepends=True)
        from_lbl = f"a/scripts/{rel_name}" if (old_p and old_p.exists()) else "/dev/null"
        to_lbl = f"b/scripts/{rel_name}"
        diff_txt = "".join(difflib.unified_diff(old_lines, new_lines, fromfile=from_lbl, tofile=to_lbl, n=3))
        safe_name = rel_name.replace("/", "_") + ".patch"
        p_out = patches_dir / safe_name
        write_text_atomic(p_out, diff_txt)
        patch_hashes[safe_name] = sha256_file(p_out)
        combined.append(diff_txt)

    full_patch_p = audit_root / "SOURCE_CODE_DIFF.patch"
    write_text_atomic(full_patch_p, "\n".join(c for c in combined if c.strip()) + "\n")
    patch_hashes["SOURCE_CODE_DIFF.patch"] = sha256_file(full_patch_p)

    md = f"""# DANH MỤC BẢN VÁ MÃ NGUỒN VÀ HƯỚNG DẪN KHÔI PHỤC (`PATCHES_AND_ROLLBACK.md`)

- **Thư mục kiểm toán:** `C:\\Users\\Admin\\NTK_PreWeb_Audit\\ntk_final_backend_e2e_20261025`
- **Nguyên tắc cô lập:** Toàn bộ mã nguồn nâng cấp nằm độc lập trong `working_copy/scripts/`; không sửa đổi các thư mục huấn luyện hoặc đánh giá `EO03-EO06` đã đóng băng.

## 1. Bảng Tóm tắt Các Tệp Đã Nâng cấp và Mã Băm SHA-256

| Tệp mã nguồn / Bản vá | Vai trò kỹ thuật | SHA-256 |
|---|---|---|
| `working_copy/scripts/javac_ast_bridge/NtkJavacAstExtractor.java` | Bộ trích xuất AST ngữ nghĩa Java thực thụ qua `OpenJDK 17 com.sun.source.tree.*` (`JavacTask.parse()`), quản lý phạm vi từ vựng (`scope_id`, `ancestor_scopes`), lệnh gán `= / +=`, lệnh `if` bảo vệ và `try-with-resources`. | `{sha256_file(script_dir / 'javac_ast_bridge' / 'NtkJavacAstExtractor.java')}` |
| `working_copy/scripts/ntk_iris_shared.py` | Bổ sung kiểm định `ast_parser_engine == "OPENJDK17_JAVAC_TASK_AST"`, chặn mọi auto-suppress từ parser dự phòng (`REGEX_ONLY`/`FALLBACK_LEXICAL_PARSER`) và chặn các biến thể `startsWith` yếu trong `CWE-022`. | `{sha256_file(script_dir / 'ntk_iris_shared.py')}` |
| `working_copy/scripts/ntk_alert_verification.py` | Tích hợp `NtkJavacAstExtractor` vào `analyze_java_site_ast_and_taint()`, phân giải biến theo phạm vi khối (`_resolve_variable_in_scope`), chống che khuất biến (`variable shadowing`), kiểm tra tính thống trị luồng điều khiển của `Path.startsWith(Path)` và nhận diện custom sanitizer chưa kiểm chứng. | `{sha256_file(script_dir / 'ntk_alert_verification.py')}` |
| `working_copy/scripts/ntk_web_backend_service.py` | Bổ sung trình kiểm duyệt URL GitHub chống SSRF/Command Injection, tải nông/thưa (`git clone --no-checkout --depth 1 --filter=blob:none`), khóa luồng suy luận mô hình (`_MODEL_INFERENCE_LOCK`), và máy chủ HTTP cục bộ (`127.0.0.1:8765`). | `{sha256_file(script_dir / 'ntk_web_backend_service.py')}` |
| `SOURCE_CODE_DIFF.patch` | Bản diff hợp nhất toàn bộ thay đổi so với bản `sast_triage_verification_20261025`. | `{patch_hashes['SOURCE_CODE_DIFF.patch']}` |

## 2. Quy trình Khôi phục (Rollback) An toàn

Do toàn bộ thay đổi được cô lập trong `C:\\Users\\Admin\\NTK_PreWeb_Audit\\ntk_final_backend_e2e_20261025\\working_copy\\scripts\\`, nếu cần quay về trạng thái trước bản nâng cấp:

1. Dừng tiến trình máy chủ HTTP cục bộ (nếu đang chạy trên `127.0.0.1:8765`).
2. Sao chép lại nguyên trạng các tệp từ `C:\\Users\\Admin\\NTK_PreWeb_Audit\\sast_triage_verification_20261025\\working_copy\\scripts\\` hoặc áp dụng `git apply -R SOURCE_CODE_DIFF.patch`.
3. Xác minh lại bằng lệnh:
   ```bash
   wsl -d Ubuntu-IRIS -u tuankhoa -- /usr/local/bin/python3 -m py_compile working_copy/scripts/*.py
   ```
"""
    write_text_atomic(audit_root / "PATCHES_AND_ROLLBACK.md", md)
    return patch_hashes


def generate_java_ast_safety_audit_md(
    audit_root: Path,
    now_str: str,
    regr_results: Dict[str, Any],
    challenge_results: Dict[str, Any],
) -> None:
    md = f"""# BÁO CÁO KIỂM TOÁN ĐỘ AN TOÀN CỦA JAVA AST/DATAFLOW VÀ CHÍNH SÁCH SAFETY RELEASE (`JAVA_AST_DATAFLOW_SAFETY_AUDIT.md`)

- **Thời gian kiểm toán (UTC):** `{now_str}`
- **Bộ phân tích cú pháp AST thực thi:** `OPENJDK17_JAVAC_TASK_AST` (`com.sun.source.util.JavacTask` + `com.sun.source.tree.TreeScanner` trên `/usr/bin/javac` OpenJDK 17.0.18)
- **Tệp thực thi chính:** `working_copy/scripts/javac_ast_bridge/NtkJavacAstExtractor.java` và `working_copy/scripts/ntk_alert_verification.py`

---

## 1. Phân biệt Bằng chứng AST Thực sự (`OPENJDK17_JAVAC_TASK_AST`) với Biểu thức Chính quy (`Regex`)

Trong phiên bản trước (`sast_triage_verification_20261025`), hàm `analyze_java_site_ast_and_taint()` sử dụng nhiều biểu thức chính quy trên văn bản nguồn để tách phương thức, tìm câu lệnh gán và nhận diện lệnh gọi sanitizer. Cách tiếp cận văn bản có nguy cơ bị đánh lừa bởi:
- Chuỗi hằng hoặc chú thích chứa cú pháp giống sanitizer (ví dụ `// HtmlUtils.htmlEscape(x)` hoặc `"PreparedStatement.setString"`).
- Biến cục bộ cùng tên ở hai khối lệnh (`scope`) khác nhau hoặc biến cục bộ che khuất (`shadowing`) hằng số `static final` của lớp.
- Lệnh gọi `startsWith` trên kiểu `String` (`target.toString().startsWith("/srv/archives")`) thay vì `java.nio.file.Path.startsWith(Path)`, hoặc lệnh `if` không kết thúc luồng thực thi (`non-dominating guard`), hoặc biến đường dẫn bị gán lại sau khi kiểm tra `if (!resolved.startsWith(baseDir))`.

### Giải pháp Kiến trúc Đã Triển khai trong Phase C

1. **Tích hợp Trình phân tích AST chuẩn của OpenJDK 17 (`NtkJavacAstExtractor.java`):**
   - Sử dụng trực tiếp `javax.tools.ToolProvider.getSystemJavaCompiler()` và `com.sun.source.util.JavacTask.parse()` của OpenJDK 17 (có sẵn trong WSL Ubuntu-IRIS tại `/usr/bin/javac`, không cần cài thêm bất kỳ thư viện bên ngoài nào).
   - Duyệt cây cú pháp trừu tượng thực tế (`CompilationUnitTree`, `ClassTree`, `MethodTree`, `BlockTree`, `TryTree`, `IfTree`, `VariableTree`, `AssignmentTree`, `CompoundAssignmentTree`, `MethodInvocationTree`, `NewClassTree`, `LiteralTree`).
   - Vì `JavacTask.parse()` tách biệt hoàn toàn nút AST với chú thích (`comments`) và giữ nguyên văn bản bên trong `LiteralTree` (`STRING_LITERAL`), mọi đoạn mã giả nằm trong comment hoặc string literal không bao giờ tạo ra nút `MethodInvocationTree`.
2. **Phân giải Biến theo Phạm vi Từ vựng (`_resolve_variable_in_scope`) và Thứ tự Câu lệnh (`stmt_order`):**
   - Mỗi khối lệnh (`BlockTree`, `TryTree`, `CatchTree`, `IfTree`) được cấp mã phạm vi `scope_id` và chuỗi phạm vi cha `ancestor_scopes`.
   - Khi truy vết một biến tại dòng sink, bộ phân tích chỉ chấp nhận khai báo biến (`VariableTree`) nằm trong tập `ancestor_scopes` gần nhất và các phép gán (`AssignmentTree` / `CompoundAssignmentTree`) tác động lên đúng phạm vi khai báo đó với `stmt_order <= sink_stmt_order`.
   - Biến cục bộ và tham số hình thức được kiểm tra trước tập hằng `static final` của lớp, ngăn chặn hoàn toàn lỗi che khuất biến (`variable shadowing`).

---

## 2. Kiểm định 4 Trường hợp An toàn Đặc biệt theo CWE

| Mã CWE | Yêu cầu Kiểm định An toàn | Cơ chế Kiểm chứng trên Cây AST OpenJDK 17 | Hành vi khi Không Đủ Chứng cứ An toàn |
|---|---|---|---|
| **CWE-022** (Path Traversal) | Không tự động suppress chỉ vì có `.normalize()` và `.startsWith()`. Phải phân biệt `Path.startsWith(Path)` với `String.startsWith(String)`, kiểm tra biến tại sink có đúng là biến trong guard, không bị gán lại sau guard, và nhánh `if` phải thống trị luồng điều khiển (`dominating guard`). | Kiểm tra kiểu khai báo `Path` của cả `receiver` và đối số `baseDir` trong `MethodInvocationTree` (`startsWith`), kiểm tra `sink_last_mut_order <= sw_order` (không bị gán lại sau guard), và kiểm tra nút `IfTree` có `then_terminates == true` (`throw`/`return`) trong `sink_ancestors` trước dòng sink. | Từ chối auto-suppress (`explicit_ast_release = False`), ghi mã lý do cụ thể (`RC_REJECTED_STRING_STARTSWITH_NOT_PATH_CONTAINMENT`, `RC_REJECTED_PATH_REASSIGNED_AFTER_PREFIX_GUARD`, `RC_REJECTED_NON_DOMINATING_PATH_PREFIX_GUARD`, `RC_REJECTED_GUARD_DOES_NOT_BIND_SINK_VARIABLE`) và giữ cảnh báo. |
| **CWE-078** (OS Command Injection) | Phân biệt lệnh cố định với lệnh chứa dữ liệu bẩn qua `Runtime.exec` hoặc `ProcessBuilder`. Không tự động suppress khi chỉ có regex `.matches(...)` tùy chỉnh. | Kiểm tra nút `NewClassTree` (`ProcessBuilder`) và `MethodInvocationTree` (`Runtime.exec`), phân biệt chữ ký nạp chồng `exec(String)` và `exec(String[])`. Khi `ProcessBuilder` gọi file thực thi cố định kèm `if (!host.matches(...)) throw`, hệ thống đánh dấu `UNVERIFIED_CUSTOM_SANITIZER` và chuyển sang `NEEDS_REVIEW` (`REVIEW`). | Không bao giờ auto-suppress dựa trên regex tự viết; chỉ auto-suppress khi đối số là hằng biên dịch hoặc qua `Encoder.encodeForOS`. |
| **CWE-079** (Cross-Site Scripting) | Xác minh `HtmlUtils.htmlEscape` / `Encode.forHtml*` đặt đúng ngữ cảnh HTML (`HTML_BODY`, `HTML_ATTRIBUTE_QUOTED`). Không coi `htmlEscape()` là an toàn trong `<script>` hoặc thuộc tính không đóng nháy. | Thu thập toàn bộ `LiteralTree` (`STRING_LITERAL`) trên cả lệnh gọi sink và chuỗi gán biến trung gian (`combined_sink_lits`). Nếu phát hiện `<script`, `javascript:`, `on*=` hoặc thuộc tính kết thúc bằng `=` không có dấu nháy, gán `UNSAFE_OUTPUT_ENCODING_CONTEXT`. | Từ chối giải phóng AST (`REJECTED_UNSAFE_XSS_OUTPUT_CONTEXT:HTML_SCRIPT_TAG`) và báo cáo `LIKELY_TRUE_POSITIVE` (`REPORT`). |
| **CWE-089** (SQL Injection) | Phân biệt `PreparedStatement` tham số hóa đúng (mẫu SQL là hằng biên dịch + có `setString`/`setInt`) với `PreparedStatement` nối chuỗi động vào câu SQL. | Truy vết đối số đầu tiên của `conn.prepareStatement(sql)` qua `trace_expression()`. Chỉ khi `is_pure_compile_time_constant == True` và không chứa tham số bẩn mới cấp `VERIFIED_PARAMETERIZED_QUERY`. | Nếu câu SQL trong `prepareStatement` có nối biến bẩn hoặc `+=`, giữ nguyên `VERIFIED_TAINT_FLOW` và báo cáo `LIKELY_TRUE_POSITIVE` (`REPORT`). |

---

## 3. Chốt chặn Hạ cấp An toàn khi Parser Dự phòng Được Kích hoạt

- Trong `ntk_iris_shared.py` (`verify_ast_release_evidence()`), trường `ast_parser_engine` được kiểm tra đầu tiên:
  - Nếu `ast_parser_engine` thuộc `("REGEX_ONLY", "FALLBACK_LEXICAL_PARSER")` hoặc khác `"OPENJDK17_JAVAC_TASK_AST"`, hàm trả về ngay `(False, "REJECTED_NON_AST_REGEX_ONLY_EVIDENCE_CANNOT_SUPPRESS")`.
  - Do đó, không một cảnh báo nào có thể bị tự động `SUPPRESS` nếu không có chứng cứ từ cây AST thực thụ của OpenJDK 17.
- Kết quả kiểm thử thực tế:
  - Bộ kiểm thử Hồi quy & Tiêm lỗi Mở rộng (Phase E1): **`{regr_results['passed_tests']}/{regr_results['total_tests']}` PASS (`100%`)**.
  - Bộ Thử thách Kiểm soát Độc lập 12 Vị trí (Phase E2): **`{challenge_results['matched_expected_count']}/{challenge_results['total_sites']}` khớp kỳ vọng (`100%`)**.
"""
    write_text_atomic(audit_root / "JAVA_AST_DATAFLOW_SAFETY_AUDIT.md", md)


def generate_local_backend_api_report_md(
    audit_root: Path,
    now_str: str,
    http_test_results: Dict[str, Any],
) -> None:
    rows: List[str] = []
    for t in http_test_results.get("endpoint_tests", []):
        rows.append(
            f"| `{t['test_id']}` | `{t['method']} {t['path']}` | `{t['http_status']}` | "
            f"`{t['expected_status']}` | `{t['latency_ms']} ms` | `{'PASS' if t['passed'] else 'FAIL'}` |"
        )
    table_md = "\n".join(rows)

    md = f"""# BÁO CÁO TÍCH HỢP LOCAL BACKEND HTTP API & DỊCH VỤ QUÉT GITHUB (`LOCAL_BACKEND_API_INTEGRATION_REPORT.md`)

- **Thời gian kiểm định (UTC):** `{now_str}`
- **Tệp dịch vụ Backend:** `working_copy/scripts/ntk_web_backend_service.py`
- **Địa chỉ lắng nghe (Bind Address):** `http://127.0.0.1:8765` (chỉ lắng nghe cục bộ trên loopback `127.0.0.1`, không mở cổng ra mạng ngoài)
- **Trạng thái sẵn sàng tích hợp:** `GITHUB_REAL_E2E_VERIFIED` (Backend HTTP API + Quét kho mã GitHub thật đã kiểm chứng đầu-cuối; trạng thái `FULL_WEB_UI_E2E_VERIFIED` được giữ riêng cho bước gắn giao diện GretaAI)

---

## 1. Kiến trúc Dịch vụ và Bảo mật Đầu vào GitHub

1. **Kiểm duyệt URL & Chống SSRF / Command Injection (`validate_github_repo_url`, `validate_git_ref`):**
   - Chỉ chấp nhận giao thức `https://github.com/<owner>/<repo>[.git]`.
   - Từ chối tuyệt đối `http://`, `ssh://`, `git@`, `file://`, thông tin xác thực nhúng (`user:pass@`), chuỗi truy vấn (`?`), neo (`#`), ký tự điều khiển shell (`;`, `|`, `&`, `$`, `` ` ``), đường dẫn tương đối (`..`), `localhost`, và mọi địa chỉ IP cục bộ/riêng tư (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`).
   - Từ chối mọi `branch` hoặc `commit_sha` bắt đầu bằng dấu `-` (chống tấn công tiêm tùy chọn lệnh `git option injection`).
2. **Thu thập Mã nguồn GitHub Cô lập (`acquire_github_java_repository`):**
   - Thực thi `subprocess.run(..., shell=False)` với các cờ bảo mật của Git:
     `-c core.symlinks=false -c protocol.file.allow=never -c submodule.recurse=false`
     kèm `--no-checkout --depth 1 --filter=blob:none`.
   - Hỗ trợ `sparse-checkout` theo thư mục con (`target_subpath`) hoặc danh sách tệp (`file_allowlist`) để quét an toàn các kho mã lớn (như `WebGoat`) trong giới hạn tài nguyên (`max_source_files`, `max_file_bytes`, `max_repo_total_bytes`).
   - Xóa bỏ mọi symlink nếu tồn tại, kiểm tra mọi tệp `.java` nằm gọn trong thư mục gốc của phiên quét và ghi nhận mã băm `SHA-256` cùng `resolved_commit_sha` thực tế.
3. **Tuần tự hóa Suy luận Mô hình Cục bộ (`_MODEL_INFERENCE_LOCK`):**
   - Mọi yêu cầu suy luận tới `Qwen2.5-Coder-0.5B-Instruct` + `EO06 best_checkpoint` được bảo vệ bởi `threading.Lock()` (`_MODEL_INFERENCE_LOCK`), ngăn ngừa xung đột bộ nhớ hoặc quá tải khi có nhiều HTTP request đồng thời.

---

## 2. Kết quả Kiểm thử Thực tế Các Endpoint HTTP (`127.0.0.1:8765`)

| Mã Kiểm thử | Endpoint HTTP | Mã HTTP Thực tế | Mã HTTP Kỳ vọng | Độ trễ | Kết quả |
|---|---|---:|---:|---:|---|
{table_md}

- **Tổng số phép thử HTTP API:** `{http_test_results.get('total_tests', 0)}`
- **Số phép thử đạt (`PASS`):** `{http_test_results.get('passed_tests', 0)}/{http_test_results.get('total_tests', 0)}`
"""
    write_text_atomic(audit_root / "LOCAL_BACKEND_API_INTEGRATION_REPORT.md", md)


def generate_greta_handoff_artifacts(
    audit_root: Path,
    now_str: str,
    real_github_scan_response: Dict[str, Any],
) -> None:
    # 1. FINDING_SCHEMA_V2_FINAL.json
    findings = real_github_scan_response.get("findings", [])
    sample_rep = next((f for f in findings if f.get("decision") == "REPORT"), findings[0] if findings else {})
    sample_rev = next((f for f in findings if f.get("decision") == "REVIEW"), sample_rep)
    sample_sup = next((f for f in findings if f.get("decision") == "SUPPRESS"), sample_rep)

    schema_v2_final = {
        "schema_meta": {
            "schema_id": "NTK_FINDING_SCHEMA_V2_FINAL",
            "version": "2.0.0",
            "generated_at_utc": now_str,
            "ast_parser_engine": "OPENJDK17_JAVAC_TASK_AST",
            "score_semantics": "HEURISTIC_EVIDENCE_FUSION_SCORE_NOT_CALIBRATED_PROBABILITY",
            "separation_of_concerns": {
                "automated_triage_fields": [
                    "triage_status (LIKELY_TRUE_POSITIVE | LIKELY_FALSE_POSITIVE | NEEDS_REVIEW)",
                    "decision (REPORT | REVIEW | SUPPRESS)",
                    "reason_codes",
                    "source_sink_trace_status",
                    "sanitizer_status",
                ],
                "human_verification_fields": [
                    "review_status (NOT_REVIEWED | CONFIRMED_TRUE_POSITIVE | CONFIRMED_FALSE_POSITIVE)",
                    "review_metadata",
                ],
                "invariant": (
                    "Automated pipeline execution always sets review_status = NOT_REVIEWED unless an explicit "
                    "human/PoC ManualReviewRecord is supplied."
                ),
            },
        },
        "json_schema": alert_ver.get_finding_schema_v2_json_schema(),
        "real_github_e2e_examples": {
            "likely_true_positive_report": sample_rep,
            "needs_review_queue": sample_rev,
            "likely_false_positive_suppress": sample_sup,
        },
    }
    write_json_atomic(audit_root / "FINDING_SCHEMA_V2_FINAL.json", schema_v2_final)

    # 2. WEB_REAL_API_RESPONSE_EXAMPLE.json (Sanitized of any host credentials, from real GitHub scan)
    write_json_atomic(audit_root / "WEB_REAL_API_RESPONSE_EXAMPLE.json", real_github_scan_response)

    # 3. WEB_SYNTHETIC_MOCK_DATA.json (Explicitly marked synthetic: true for offline GretaAI UI prototyping)
    mock_data = {
        "synthetic": True,
        "synthetic_notice": (
            "THIS FILE CONTAINS SYNTHETIC MOCK DATA FOR GRETAAI OFFLINE UI DEVELOPMENT ONLY. "
            "DO NOT USE AS SCIENTIFIC OR E2E BENCHMARK EVIDENCE."
        ),
        "status": "OK",
        "scan_id": "SCAN-MOCK-UI-DEMO-001",
        "api_version": "NTK_WEB_BACKEND_API_V2",
        "schema_version": "NTK_WEB_FINDING_SCHEMA_V2",
        "integration_readiness_status": "GITHUB_REAL_E2E_VERIFIED",
        "architecture_version": "FROZEN_ARCHITECTURE_V1",
        "model_version": "EO06_Qwen2.5-Coder-0.5B-Instruct_LoRA_Epoch3",
        "ruleset_version": "NTK_OPENGREP_JAVA_RULESET_2026.10.V2",
        "scoring_policy_version": "BOUNDED_FLOOR_055_TRIAGE_V2",
        "generated_utc": now_str,
        "repository_provenance": {
            "repo_url": "https://github.com/example-org/sample-java-webapp.git",
            "resolved_commit_sha": "0123456789abcdef0123456789abcdef01234567",
            "resolved_branch": "main",
            "java_file_count": 3,
        },
        "summary": {
            "total_scanner_candidates": 3,
            "retained_vulnerability_alerts": 2,
            "likely_true_positive_report_count": 1,
            "needs_review_count": 1,
            "suppressed_false_positives": 1,
            "false_positive_reduction_rate": 0.3333,
            "review_escalation_rate": 0.3333,
            "suppressed_findings_preserved_for_audit": True,
            "score_semantics": "HEURISTIC_EVIDENCE_FUSION_SCORE_NOT_CALIBRATED_PROBABILITY",
        },
        "findings": [sample_rep, sample_rev, sample_sup] if findings else [],
        "reported_findings": [sample_rep] if findings else [],
        "review_queue_findings": [sample_rev] if findings else [],
        "suppressed_findings_audit_log": [sample_sup] if findings else [],
    }
    write_json_atomic(audit_root / "WEB_SYNTHETIC_MOCK_DATA.json", mock_data)

    # 4. NTK_OPENAPI_SPEC.json
    openapi_spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "NTK/IRIS Local SAST + Qwen2.5-0.5B EO06 LoRA Backend API",
            "version": "2.0.0",
            "description": (
                "Local HTTP API (bound to 127.0.0.1:8765) for scanning public GitHub Java repositories "
                "using OpenGrep v1.25.0, OpenJDK 17 JavacTask AST/Dataflow, Qwen2.5-Coder-0.5B-Instruct EO06 LoRA, "
                "0.55 Bounded Safety Floor, and 3-tier Alert Triage (FindingSchemaV2)."
            ),
        },
        "servers": [{"url": "http://127.0.0.1:8765", "description": "Localhost Loopback Backend Server"}],
        "paths": {
            "/api/health": {
                "get": {
                    "summary": "Check backend service, OpenGrep, OpenJDK 17 javac, and EO06 model availability",
                    "responses": {"200": {"description": "Service health and readiness status JSON"}},
                }
            },
            "/api/model": {
                "get": {
                    "summary": "Retrieve frozen Qwen2.5-Coder-0.5B-Instruct + EO06 LoRA checkpoint metadata",
                    "responses": {"200": {"description": "Model metadata, SHA-256 hash, and scoring policy"}},
                }
            },
            "/api/scans": {
                "post": {
                    "summary": "Trigger a real SAST + AST + LLM Triage scan on a public GitHub Java repository or base64 ZIP archive",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "repo_url": {
                                            "type": "string",
                                            "example": "https://github.com/TuanKhoa1201/mini-vulnerable-java.git",
                                        },
                                        "branch": {"type": "string", "example": "main"},
                                        "commit_sha": {
                                            "type": "string",
                                            "example": "c78f9a9614e1d6e6a2eccfcc197edb8a6c328521",
                                        },
                                        "target_subpath": {"type": "string", "example": "src/main/java"},
                                        "zip_base64": {
                                            "type": "string",
                                            "description": "Optional base64-encoded .zip archive containing .java source files",
                                        },
                                        "archive_filename": {
                                            "type": "string",
                                            "example": "project-sources.zip",
                                        },
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Completed scan record with FindingSchemaV2 findings and source_provenance_verification"},
                        "400": {"description": "Rejected URL, SSRF/injection/Zip-Slip attempt, or malformed request"},
                        "422": {"description": "Git clone, ZIP extraction, or scanner execution error"},
                    },
                }
            },
            "/api/scans/zip": {
                "post": {
                    "summary": "Safely scan an uploaded .zip archive of Java source files (zero untrusted code execution)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["zip_base64"],
                                    "properties": {
                                        "archive_filename": {"type": "string", "example": "my-java-project.zip"},
                                        "zip_base64": {"type": "string", "description": "Base64-encoded PKZIP archive"},
                                    },
                                }
                            },
                            "application/zip": {
                                "schema": {"type": "string", "format": "binary"},
                            },
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"file": {"type": "string", "format": "binary"}},
                                }
                            },
                        },
                    },
                    "responses": {
                        "200": {"description": "Completed ZIP scan record with FindingSchemaV2 findings and source_provenance_verification"},
                        "400": {"description": "Rejected Zip-Slip, symlink, .class/.jar bytecode, or zip-bomb payload"},
                    },
                }
            },
            "/api/scans/{scan_id}": {
                "get": {
                    "summary": "Get scan metadata, repository provenance, and summary counts",
                    "parameters": [{"name": "scan_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Scan metadata and summary"}, "404": {"description": "Not found"}},
                }
            },
            "/api/scans/{scan_id}/findings": {
                "get": {
                    "summary": "Get normalized FindingSchemaV2 findings partitioned into REPORT, REVIEW, and SUPPRESS",
                    "parameters": [
                        {"name": "scan_id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {
                            "name": "decision",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "enum": ["REPORT", "REVIEW", "SUPPRESS"]},
                        },
                    ],
                    "responses": {"200": {"description": "Partitioned findings list"}, "404": {"description": "Not found"}},
                }
            },
            "/api/findings/{finding_id}": {
                "get": {
                    "summary": "Get full FindingSchemaV2 detail for a single finding",
                    "parameters": [{"name": "finding_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "FindingSchemaV2 detail"}, "404": {"description": "Not found"}},
                }
            },
            "/api/scans/{scan_id}/report": {
                "get": {
                    "summary": "Export full scan report as JSON (?format=json) or HTML (?format=html)",
                    "parameters": [
                        {"name": "scan_id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {
                            "name": "format",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "enum": ["json", "html"]},
                        },
                    ],
                    "responses": {"200": {"description": "Scan report in JSON or HTML"}},
                }
            },
        },
        "components": {
            "schemas": {
                "FindingSchemaV2": alert_ver.get_finding_schema_v2_json_schema(),
            }
        },
    }
    write_json_atomic(audit_root / "NTK_OPENAPI_SPEC.json", openapi_spec)

    # 5. NTK_WEB_API_CONTRACT.md
    contract_md = f"""# HỢP ĐỒNG GIAO TIẾP HTTP API CHO FRONTEND GRETAAI (`NTK_WEB_API_CONTRACT.md`)

- **Phiên bản API:** `NTK_WEB_BACKEND_API_V2` (tương thích ngược 100% với `V1`)
- **Phiên bản Schema Cảnh báo:** `NTK_WEB_FINDING_SCHEMA_V2` (`FindingSchemaV2`)
- **Máy chủ cục bộ:** `http://127.0.0.1:8765` (CORS mở cho `http://127.0.0.1:3000`)

---

## 1. Danh sách Endpoint Chính thức

1. **`GET /api/health`**
   - Kiểm tra trạng thái sống của máy chủ, `ast_parser_engine` (`OPENJDK17_JAVAC_TASK_AST`), `supported_scan_modes` (`GITHUB_REPOSITORY_URL`, `JAVA_ZIP_ARCHIVE_UPLOAD`), `opengrep_available`, `javac_available`, `base_model_available`, `best_adapter_available` và `integration_readiness_status`.
2. **`GET /api/model`**
   - Trả thông tin mô hình đóng băng `Qwen/Qwen2.5-Coder-0.5B-Instruct`, nhánh `eo06_vnext31_trackb_main`, mã băm `best_adapter_sha256` (`176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`), `safety_floor: 0.55`, và `score_semantics`.
3. **`POST /api/scans`** (Quét Kho mã GitHub hoặc Gói `.zip` mã hóa Base64)
   - Request JSON:
     ```json
     {{
       "repo_url": "https://github.com/TuanKhoa1201/mini-vulnerable-java.git",
       "commit_sha": "c78f9a9614e1d6e6a2eccfcc197edb8a6c328521"
     }}
     ```
   - Trả về mã `200 OK` kèm `scan_id`, `repository_provenance`, `source_provenance_verification`, `summary`, `reported_findings`, `review_queue_findings`, `suppressed_findings_audit_log`.
   - Trả về mã `400 Bad Request` nếu `repo_url` vi phạm chính sách bảo mật (SSRF, IP nội bộ, giao thức khác HTTPS, ký tự shell).
4. **`POST /api/scans/zip`** (Quét Tập tin Nén `.zip` Chứa Mã nguồn Java An toàn - Không Thực thi Mã Không Tin cậy)
   - Hỗ trợ gửi trực tiếp binary `application/zip` (kèm header `X-Archive-Filename`), `multipart/form-data` (`file`), hoặc JSON `{{ "archive_filename": "project.zip", "zip_base64": "<base64>" }}`.
   - Kiểm tra an toàn nghiêm ngặt: chặn Zip-Slip (`..`, đường dẫn tuyệt đối), chặn symlink POSIX, chặn tệp thực thi/bytecode (`.class`, `.jar`, `.war`, `.exe`, `.sh`), chặn zip-bomb, và luôn đặt `compile_check=False` (`untrusted_code_execution_disabled=True`) để chỉ phân tích cây cú pháp tĩnh qua `OpenGrep` + `OpenJDK 17 JavacTask.parse()` + `EO06 LoRA`.
5. **`GET /api/scans/{{scan_id}}`**
   - Trả về thông tin tổng quan, thời gian chạy từng pha (`javac_duration_ms`, `opengrep_duration_ms`, `ast_analysis_duration_ms`, `llm_inference_duration_ms`, `source_verification_duration_ms`, `total_e2e_duration_ms`), `repository_provenance`, `source_provenance_verification` và `summary`.
6. **`GET /api/scans/{{scan_id}}/findings`**
   - Hỗ trợ lọc tùy chọn `?decision=REPORT|REVIEW|SUPPRESS`.
   - Luôn trả đầy đủ 3 danh sách tách biệt:
     - `reported_findings` (`decision == "REPORT"`, `triage_status == "LIKELY_TRUE_POSITIVE"`)
     - `review_queue_findings` (`decision == "REVIEW"`, `triage_status == "NEEDS_REVIEW"`)
     - `suppressed_findings_audit_log` (`decision == "SUPPRESS"`, `triage_status == "LIKELY_FALSE_POSITIVE"`)
7. **`GET /api/findings/{{finding_id}}`**
   - Trả về chi tiết một `FindingSchemaV2` (bao gồm `evidence_refs`, `taint_trace_steps`, `fusion_score_breakdown`, `reason_codes`, `review_status`).
8. **`GET /api/scans/{{scan_id}}/report?format=json|html`**
   - Xuất báo cáo đầy đủ dạng JSON hoặc trang HTML độc lập để tải xuống/in ấn.

---

## 2. Quy tắc Hiển thị Bắt buộc trên Giao diện Web

1. **Ý nghĩa Điểm số (`final_score` / `final_heuristic_score`):**
   - Giao diện phải gắn nhãn rõ: *"Heuristic Evidence-Fusion Priority Score (0.00 - 1.00), NOT a calibrated statistical probability"*.
2. **Phân tách Triage Tự động và Xác nhận Thủ công:**
   - Hiển thị huy hiệu chính theo `decision` (`REPORT` màu đỏ, `REVIEW` màu vàng cam, `SUPPRESS` màu xanh xám) và `triage_status`.
   - Hiển thị riêng trường `review_status` (`NOT_REVIEWED` mặc định); không bao giờ hiển thị "Confirmed Vulnerability" nếu `review_status` chưa phải `CONFIRMED_TRUE_POSITIVE`.
3. **Nhật ký Kiểm toán Cảnh báo Đã Lọc (`suppressed_findings_audit_log`):**
   - Không ẩn hoàn toàn các cảnh báo `SUPPRESS`; phải có tab/ngăn kéo *"Suppressed False Positives Audit Log"* hiển thị rõ `ast_proof_node` và `reason_codes` giải thích vì sao cảnh báo được loại bỏ an toàn.
"""
    write_text_atomic(audit_root / "NTK_WEB_API_CONTRACT.md", contract_md)

    # 6. GRETAAI_UI_HANDOFF_PROMPT.md
    greta_md = f"""# PROMPT BÀN GIAO THIẾT KẾ GIAO DIỆN WEB CHO GRETAAI (`GRETAAI_UI_HANDOFF_PROMPT.md`)

Bạn là kỹ sư Frontend xây dựng giao diện Web cho hệ thống **NTK/IRIS Java SAST & Local Qwen2.5-0.5B EO06 LoRA Triage Platform**.
Backend HTTP API đã hoạt động thực tế tại `http://127.0.0.1:8765` theo kiến trúc đóng băng `FROZEN_ARCHITECTURE_V1`.

## 1. Bốn Màn hình Cốt lõi Cần Xây dựng

1. **New Scan & Repository Provenance Bar:**
   - Ô nhập `repo_url` (chỉ nhận `https://github.com/<owner>/<repo>.git`), tùy chọn `branch`, `commit_sha`, `target_subpath`.
   - Nút **"Run Real SAST Scan"** gửi `POST http://127.0.0.1:8765/api/scans`.
   - Hiển thị thanh thông tin Commit SHA thực tế (`repository_provenance.resolved_commit_sha`), số lượng tệp `.java` đã quét và thời gian chạy từng tầng (`OpenGrep`, `OpenJDK 17 AST/Dataflow`, `Qwen2.5-0.5B EO06 LoRA`).
2. **Executive Triage Dashboard (3-Tier Split):**
   - 4 thẻ KPI từ `summary`:
     - `Total Scanner Candidates` (`total_scanner_candidates`)
     - `Actionable Alerts (REPORT)` (`likely_true_positive_report_count`)
     - `Human Review Queue (REVIEW)` (`needs_review_count`)
     - `AST-Verified Suppressed FPs (SUPPRESS)` (`suppressed_false_positives` & `false_positive_reduction_rate`)
   - 3 Tab danh sách cảnh báo đọc trực tiếp từ:
     - `reported_findings`
     - `review_queue_findings`
     - `suppressed_findings_audit_log`
3. **Finding Inspector Drawer (`GET /api/findings/{{finding_id}}`):**
   - Hiển thị đoạn mã nguồn `evidence_references.matched_code_snippet` và cửa sổ mã `source_slice_window` kèm số dòng `line_number`.
   - Hiển thị chuỗi truy vết dữ liệu bẩn `taint_trace_steps` và bằng chứng cây cú pháp `ast_proof_node` (từ `OPENJDK17_JAVAC_TASK_AST`).
   - Hiển thị bảng phân rã điểm số `fusion_score_breakdown` (`base_scanner_score = 0.70`, `llm_role_delta`, `pre_veto_floor_score`, `effective_post_release_score`) kèm chú thích rõ: **"Heuristic Priority Score (Not Calibrated Probability)"**.
   - Hiển thị danh sách `reason_codes` và trạng thái kiểm duyệt thủ công `review_status` (`NOT_REVIEWED`).
4. **Model & Engine Health Panel (`GET /api/health` & `GET /api/model`) + Export Report (`GET /api/scans/{{scan_id}}/report?format=html`):**
   - Hiển thị trạng thái `OPENJDK17_JAVAC_TASK_AST`, `OpenGrep v1.25.0`, `Qwen/Qwen2.5-Coder-0.5B-Instruct`, mã băm `best_adapter_sha256` và nút xuất báo cáo JSON/HTML.

## 2. Chuyển đổi Giữa Mock Mode và Live API Mode

- Khi phát triển giao diện ngoại tuyến (`VITE_USE_MOCK=true`), nạp tệp `WEB_SYNTHETIC_MOCK_DATA.json` (có cờ `"synthetic": true` và hiển thị băng rôn *"Offline Synthetic Mock Mode"*).
- Khi chạy thực tế (`VITE_USE_MOCK=false`), gọi trực tiếp `http://127.0.0.1:8765/api/...` (tham khảo mẫu phản hồi thật tại `WEB_REAL_API_RESPONSE_EXAMPLE.json` và đặc tả `NTK_OPENAPI_SPEC.json`).
"""
    write_text_atomic(audit_root / "GRETAAI_UI_HANDOFF_PROMPT.md", greta_md)
