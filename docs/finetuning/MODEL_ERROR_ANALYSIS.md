# MODEL ERROR ANALYSIS REPORT
**Model Evaluated:** QLoRA V3 (`best_adapter`) on 330 Test Samples
**Ground Truth vs. Prediction Confusion Matrix:**
- Labels: `['source', 'sink', 'taint-propagator', 'none']`
- Matrix:
  - `source` (109): TP=72, FP_as_sink=6, FP_as_prop=17, FP_as_none=14
  - `sink` (59): FP_as_src=4, TP=49, FP_as_prop=0, FP_as_none=6
  - `taint-propagator` (86): FP_as_src=3, FP_as_snk=2, TP=30, FP_as_none=51
  - `none` (76): FP_as_src=2, FP_as_snk=0, FP_as_prop=3, TP=71

## 1. Class-Specific Failure Modes
- **Taint-Propagator Recall Deficiency:** Propagators achieve the lowest recall (0.35) across all classes. The primary failure mode is confusion with `none`: 51 propagator samples were misclassified as `none`. This occurs because string manipulations (`substring`, `replace`) and object conversions look syntactically benign without deep dataflow semantics.
- **Source Precision vs Recall:** Source precision is high (0.89), but 14 source samples were labeled `none` due to lack of explicit servlet annotations in isolated method signatures.
- **Sink Safety:** Sinks achieve strong F1 (0.84), ensuring the highest fidelity on hazardous sinks like `Statement.execute` and `Runtime.exec`.

## 2. Downstream Mitigations
- In Stage 2 / SAST Scoring Engine, conservative demotion (gamma = 0.35) must be guarded so that missing propagator evidence does not automatically clear critical security findings.
