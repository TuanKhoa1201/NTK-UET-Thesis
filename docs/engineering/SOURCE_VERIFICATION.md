# Source export verification

This export is a curated subset of source files from the previously hash-verified local runtime packages. It contains 6 functional components, no trained checkpoints, private scanned projects or runtime result ZIPs.

Static check: all Python files parsed successfully on the authoring computer. The following **synthetic unit tests**, not a fresh Java/CodeQL/GPU execution, were run against the curated source tree:

| Component | Tests | Result |
| --- | ---: | --- |
| Local model/data worker tests | 51 | Pass |
| Native Stage 3 orchestration tests | 40 | Pass |
| Hybrid pipeline invariants | 33 | Pass |
| Hybrid lifecycle (fake backend) | 1 | Pass |
| Local workbench HTTP tests (synthetic data) | 51 | Pass |
| Dataset/SAST evaluator | 98 | Pass |
| Label review (with original package fixture and eval tool path) | 33 | Pass |
| Locked holdout metric helpers | 4 | Pass |

For the label review tests set `NTK_B39B6_TEST_TOOL` to the curated `evaluation/dataset_sast` directory, and `NTK_B39B4_TEST_PACKAGE` to the original verified B39B4 source archive. Those tests are fixture-dependent. The locked holdout test source uses a sibling import and was run with `python -B`, not `python -I`.

The holdout's original `run_and_evaluate.sh` contains a known isolated-import issue for `metric_core`. Historical predictions and final metrics were computed with the SHA-checked module-path recovery, without rerunning CodeQL or the models. None of these authoring checks makes the Git repository a self-contained fresh-install package.

The original research runtime lives outside this staged Git checkout and is not modified by publication.
