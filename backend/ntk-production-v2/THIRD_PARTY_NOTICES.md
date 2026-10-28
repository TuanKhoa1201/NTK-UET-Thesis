# Third-Party Notices and Attribution

1. **Upstream IRIS Research Framework (`iris-sast/iris`)**
   - Repository: `https://github.com/iris-sast/iris`
   - Authors: Ziyang Li, Saikat Dutta, et al.
   - License: MIT License
   - Relationship to NTK Production Release: Conceptual neuro-symbolic SAST + LLM API-role classification architecture reference. The NTK production backend replaces CodeQL with OpenGrep OSS v1.25.0 + OpenJDK 17 `JavacTask` AST (`NtkJavacAstExtractor.java`) + fine-tuned `Qwen/Qwen2.5-Coder-0.5B-Instruct` LoRA (`eo06_vnext31_trackb_main`).

2. **OpenGrep OSS (`opengrep/opengrep`)**
   - Version verified in production: `1.25.0`
   - License: LGPL-2.1 (invoked strictly as an external CLI subprocess `opengrep scan --config <rules.yaml> --json`; binary is not bundled in this source repository).

3. **OpenJDK Compiler Tree API (`jdk.compiler` / `com.sun.source.tree`)**
   - Version verified in production: OpenJDK `17.0.20.1`
   - License: GPLv2 with Classpath Exception (system JDK runtime invoked via `NtkJavacAstExtractor`).

4. **Base Large Language Model (`Qwen/Qwen2.5-Coder-0.5B-Instruct`)**
   - Repository: `https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct`
   - Snapshot SHA: `ea3f2471cf1b1f0db85067f1ef93848e38e88c25`
   - License: Apache License 2.0 (model weights are not committed to Git; loaded locally from HuggingFace cache or `NTK_BASE_MODEL_PATH`).
