# DATASET PROVENANCE AUDIT REPORT
**Audit Target:** Lineage of NTK-IRIS-STAGE3-AUGMENTED-V3-20261012

## 1. Upstream Data Sources
The dataset ingests candidate APIs from four distinct sources:
1. **Canonical 401 Ground Truth:**
   - Path: `/home/tuankhoa/migration/fine_tuning_dataset_audit_v2_20261001/21_stage3_group_reviews/113_stage3_401_canonical_gt/stage3_401_ground_truth.FROZEN.tsv`
   - Quality: High. Manually curated and frozen historical ground truth.
2. **Curated CVE Source/Sink Fix Information:**
   - Path: `/home/tuankhoa/iris/data/fix_info_source_sink.csv`
   - Quality: Medium-Low. Synthesized using substring matching heuristics (`"sql" in m_lower` -> CWE-089, `"file" in m_lower` -> CWE-022, default -> CWE-089).
3. **CodeQL Official Java Extension Models (v2.25.6):**
   - Path: `/home/tuankhoa/migration/codeql-queries-v2.25.6/java/ql/lib/ext/**/*.model.yml`
   - Quality: Medium. Authoritative for general security modeling, but positional arguments (`Argument[0]`) do not map to named Java parameters, defaulting to `p0`.
4. **OWASP Benchmark Java v1.2:**
   - Path: `/home/tuankhoa/iris/output/owasp_benchmark_CVE-2026-0005_1.0/.../results.csv`
   - Quality: Medium-Low. Heuristic signature regex matching for file and stream operations.

## 2. Forensic Vulnerabilities in Dataset Build Pipeline
- **Blind Replication of Sources:** All extracted sources were added simultaneously to CWE-089, CWE-022, CWE-078, CWE-079, and CWE-502. While some sources (e.g. `HttpServletRequest.getParameter`) are generic, treating every source as universally applicable across all threat models degrades CWE specialization.
- **Unclassified Sinks Default to SQL Injection:** Unmatched sink records in `fix_info_source_sink.csv` were assigned to `cwe-089wLLM` by an unrestricted `else:` branch, artificially skewing SQL injection sink distribution.
- **Synthetic Parameter Placeholders:** CodeQL positional sink annotations were converted to literal string `['p0']` whenever exact parameter names were unavailable, creating a train-inference mismatch with tools expecting real Java identifier names.
