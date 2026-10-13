# DATASET LEAKAGE AND CONTAMINATION AUDIT
**Audit Target:** NTK-IRIS-STAGE3-AUGMENTED-V3-20261012

## 1. Summary of Leakage Vectors
| Leakage Vector | Evaluated Metric | Status | Finding Details |
|---|:---:|:---:|---|
| **Class-Level Overlap** | 0 shared classes | **PASS** | Hashes of `(package, class)` ensured strict disjointness at the class boundary. |
| **Method-Level Overlap** | 0 shared methods | **PASS** | No identical `(package, class, method)` triplets between Train and Test. |
| **Signature-Level Overlap** | 37 shared signatures | **WARNING** | 37 identical signatures appear across different classes in Train and Test (e.g. standard getters/setters and close/flush methods). |
| **Package-Level Overlap** | 82 shared packages | **FAIL** | 82 packages span both Train and Test. |
| **Repository Family Overlap** | 54 shared families | **FAIL** | 54 repository families leak across splits (54 / 193 = 28.0%). |
| **In-Context Prompt Collision** | 9 test collisions | **FAIL** | 9 held-out test samples are verbatim matches for few-shot examples embedded in the user prompt! |

## 2. In-Context Prompt Contamination Details
The user prompt template embeds static few-shot examples to guide model inference. The following test samples directly match these few-shot examples, giving the model an unfair in-context hint:
- `java.io.FileInputStream.FileInputStream` (Label: `sink`, Target: `CWE-022`)
- `java.io.FileInputStream.FileInputStream` (Label: `source`, Target: `CWE-079`)
- `java.io.FileInputStream.FileInputStream` (Label: `sink`, Target: `CWE-022`)
- `java.io.FileInputStream.FileInputStream` (Label: `source`, Target: `CWE-089`)
- `java.io.FileInputStream.FileInputStream` (Label: `sink`, Target: `CWE-022`)
- `java.io.FileInputStream.FileInputStream` (Label: `source`, Target: `CWE-022`)
- `org.apache.commons.lang3.SerializationUtils.deserialize` (Label: `sink`, Target: `CWE-502`)
- `org.apache.commons.lang3.SerializationUtils.deserialize` (Label: `sink`, Target: `CWE-502`)
- `org.apache.commons.lang3.SerializationUtils.deserialize` (Label: `sink`, Target: `CWE-502`)

## 3. Top Leaking Repository Families
The following repository families have substantial representation in both Train and Test:
- `com.google.common`: 2 train samples, 1 test samples
- `com.opensymphony.xwork2`: 26 train samples, 6 test samples
- `com.rabbitmq.client`: 13 train samples, 10 test samples
- `hudson`: 21 train samples, 19 test samples
- `hudson.model`: 41 train samples, 9 test samples
- `hudson.scheduler`: 1 train samples, 1 test samples
- `hudson.search`: 1 train samples, 1 test samples
- `hudson.slaves`: 2 train samples, 3 test samples
- `hudson.tools`: 7 train samples, 3 test samples
- `hudson.util`: 22 train samples, 2 test samples
- `io.jans.configapi`: 1 train samples, 1 test samples
- `jakarta.faces.context`: 8 train samples, 1 test samples
- `java.io`: 27 train samples, 17 test samples
- `java.lang`: 67 train samples, 13 test samples
- `java.net`: 11 train samples, 4 test samples
- `java.nio`: 22 train samples, 5 test samples
- `java.rmi`: 3 train samples, 1 test samples
- `java.security`: 7 train samples, 2 test samples
- `java.sql`: 34 train samples, 3 test samples
- `java.time`: 18 train samples, 1 test samples
