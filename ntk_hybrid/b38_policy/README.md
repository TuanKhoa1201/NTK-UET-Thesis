# NTK Batch 38C4 and 38D-policy-assisted (19 October 2026)

## What is ready to run

This package contains both C4 and DPA, plus a separate localhost web UI on port 8766.
It does not overwrite the working B37 web at 8765 or the prior B38R1 installation.
Use `run_c4d.sh` and `serve_policy.sh`, NOT the inherited legacy `run.sh`, `run_all.sh`
or `serve.sh`. All legacy modules are retained for audit/regression only.

C4 checks **output encoding**, not a universal HTML sanitizer. It runs fresh
CodeQL on a new 12-file JDK-only project, runs a trusted javac Trees analyzer on
the same sources, and matches its exact callsite/owner/signature to CodeQL.
It retains raw taint paths. No path is hidden with a name-based sanitizer rule.

DPA executes a fresh 24-file project with all four CWE profiles, then merges:

* CWE-22, CWE-78 and CWE-89: original native IRIS Stage 3/local LoRA sink selection,
  strict parsing, exact overload binding, CodeQL and original V2.2 scoring.
* CWE-79: declared HTTP contextual policy plus compiler encoding assessment.
  Raw LoRA outputs and a separate model-only XSS query are still recorded, but
  they do NOT provide positive AI confidence to the policy-assisted branch.

The old model-derived C and D gates remain **NOT_GRANTED**. New receipts are
stored separately in `batch38_policy_gates`, named `C4.json` and `DPA_epoch_1.json`
(or epoch_2). These are engineering scope checks, not gold benchmark scores.
No conditional fallback based on a failing LLM prediction is used: the policy
branch is declared before inference and always labeled explicitly.

## Steps on WSL

Prerequisites: frozen `~/iris`, pinned B33 result ZIP in Windows Downloads,
existing local base and adapter files, JDK 21, CodeQL/packs and OpenGrep already
used successfully in B38R1. No package installation or network download is added.
Do not run another B37/B38 hybrid scan concurrently.

After verifying the downloaded package SHA-256 and extracting to a NEW directory:

```bash
export NTK_IRIS_PYTHON="$(command -v python)"
# P is the extracted ntk_batch38c4_d_policy_web_20261019 directory.
bash "$P/run_c4d.sh" --phase C4 --arm epoch_1
# Only after C4 returns B38_C4_POLICY_SCOPED_COMPLETE:
bash "$P/run_c4d.sh" --phase DPA --arm epoch_1
# Only after DPA returns B38_DPA_POLICY_SCOPED_COMPLETE:
bash "$P/serve_policy.sh"
```

Open `http://127.0.0.1:8766`. Download D_POLICY_JAVA.zip on the page, upload it,
choose Epoch 1, and start a NEW real scan. Download result.json, report.sarif,
and evidence.zip. DPA currently scans **all four profiles together**; it does
not add a single-CWE UI selector. A fresh upload is not a replay of CLI results.
Keep the terminal running. Ctrl+C stops this server, not B37.

The program writes a separate run directory and evidence ZIP into Downloads for
C4 and DPA. C4 does not invoke a model. DPA runs the chosen checkpoint only; both
checkpoints remain unchanged. Old A/B are retained but do not substitute for the
fresh 22/78/89 checks in DPA. Minimum free-space check is 4 GiB per run, not a
promise of total storage requirements. Databases remain on disk for audit.

## Exact supported encoding proof

The trusted Java tool uses the compiler's resolved elements, AST and positions.
It NEVER loads or executes the uploaded application, HTTP handlers, or build
scripts. Annotation processing is disabled. Runtime helper heap is capped at
768 MiB; the CodeQL pipeline retains its existing time and resource bounds.

The proof accepts only a narrow pattern:

* a single dynamic string segment within supported literal HTML text wrappers
  (`p`, `div`, `span`, `h1`, `h2`, `b`, `section`) or an ordinary quoted attribute
  (`div title`, `div data-note`, and double-quoted `input value`);
* an inline literal String.replace(CharSequence,CharSequence) chain or a resolved
  static one-parameter String helper whose body is exactly one return of that chain;
* `&` replaced first with `&amp;`, then coverage of `<` -> `&lt;`, `>` -> `&gt;`,
  plus the matching enclosing quote when in an attribute. The approved quote
  replacements are `&quot;` and `&#39;`. No arbitrary replacement is allowed;
* UTF-8 conversion with StandardCharsets.UTF_8 and straight-line local bindings;
* no reassignment, appended raw dynamic segment, byte-array mutation/escape,
  unsupported control flow, ambiguous compiler binding, or changed source hash.

Helper names do not prove anything. Identity functions and incomplete encoders
remain REVIEW REQUIRED. HTML encoding in a script, URL, CSS, event handler or
unquoted attribute is NOT certified by this profile. Response aliases/wrappers
remain unsupported by the inherited CodeQL context query and are explicitly
reviewed, not reported safe. Framework sanitizers and general Java interprocedural
sanitizer recognition are not implemented in this release.

The HTTP policy itself is inherited and remains deliberately narrow: direct
HttpExchange response writes, literal HTML Content-Type, same exchange and source
position ordering. It does not prove arbitrary control-flow dominance or aliases.
A valid local encoding proof is not a certificate that the entire application
is safe, correctly configured, or free from stored/DOM XSS.

## Fixture contract and scientific limits

C4's 12 files include two raw HTML cases, two verified encoder cases, two incomplete
or identity encoders, one script-context challenge, constant HTML, plain text,
binary response, file output, and a response-stream alias.

Expected raw contextual paths: seven file presences. Expected policy-qualified
unencoded supported-context paths: two. The other raw paths remain auditable:
verified encoding is a scoped assessment; incomplete/unknown/script cases are
**review required**, not safe. No method/filename/expected label is used by the
runtime analyzer to manufacture these classifications. Expectations are outside
the Java files and are used only for acceptance tests.

DPA combines these 12 files with unchanged A/B/SQL fixtures (four each), for 24.
Its expected qualified paths are six model-derived plus two policy-assisted.
Review-required challenges are NOT silently counted as true negatives. A claimed
"8 detections / 24 files" would not be a valid accuracy measurement.

All OpenGrep findings are retained, including escaped/constant/unsupported cases.
Raw CodeQL paths are stored separately from priority-qualified evidence. The
frozen V2.2 scorer receives neutral AI (0.5) for every policy-assisted finding.
A raw model prediction `sink` cannot upgrade CWE-79's AI confidence in this mode.
Other CWEs retain their existing scoring contract. Scores are priorities, not
vulnerability probabilities or official CVSS scores.

New compiler inventories are CWE-independent. CWE-specific views and path
callsites carry the correct selected CWE and recalculated compiler record hashes;
historical source metadata is never rewritten.

## Artifacts to send back

* `00_SUMMARY.json`, `PROGRESS.json`: final status and scope, including old gates.
* `ENCODING_COMPILER_RAW.json`, `ENCODING_COMPILER_BOUND.json`: real javac evidence.
* `context_policy/cwe-79/`: fresh QL, BQRS, SARIF and declared policy bindings.
* `policy79/RAW_PATHS.json`, `QUALIFIED_PATHS.json`, `ASSESSMENTS.json`: separate layers.
* `analysis/<arm>/cwe-79/MODEL_ONLY_PATHS_NOT_POLICY.json`: independent model branch.
* `analysis/<arm>/FUSED_FINDINGS.json` and `.sarif`: all-CWE final report for DPA.
* `live/<arm>/`: original responses and exact-cache evidence, when a model was run.
* `FROZEN_BEFORE.json`, `FROZEN_AFTER.json`, provenance and output manifest.

C4 returns `B38_C4_POLICY_SCOPED_COMPLETE` only on its pinned fixture contract.
DPA returns `B38_DPA_POLICY_SCOPED_COMPLETE` only after a valid C4 receipt and its
fresh combined regression. Mismatches are `B38_POLICY_NEEDS_REVIEW`; technical
failures are `B38_BLOCKED`. Unknown uploads may complete with
`B38_POLICY_ANALYSIS_COMPLETE_NOT_A_SAFETY_VERDICT`, but do not issue a receipt.

## Authoring checks vs WSL acceptance

The release was tested with 93 inherited CPU/HTTP/subprocess tests and 38 new tests.
The new tests include real javac AST execution, mutation cases, compilation of all
24 files, replay of real archived C3 CodeQL output, six HTTP boundary tests, two clean-Java launcher tests and five
**mock CodeQL/GPU** orchestration tests. No new CodeQL or LoRA inference was run
in the authoring environment. Original QL templates and engine source remain
unchanged; the live 79 policy query gets a new identifier/provenance label only.
Actual C4, DPA and browser runs must still pass on the user's WSL.

CWE-79 model-derived failure from C/C2 remains part of the research results.
No retraining occurs here. This release does not deliver Servlet/Spring/Maven/
Gradle, full SAPipeline.run(), Stage 4, independent gold validation or general
sanitizer support. Its value is a transparent, local, mixed-evidence prototype.
