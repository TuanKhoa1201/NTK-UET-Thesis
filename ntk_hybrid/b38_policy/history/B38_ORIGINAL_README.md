# NTK Batch 38 A/B/C/D - staged four-CWE local hybrid prototype

## Release boundary

This package is an implementation to be validated on WSL, **not an already
accepted four-CWE experiment**. New CodeQL queries, OpenGrep rules and GPU
inference have NOT been run in the authoring container. CPU tests, real local
HTTP tests, actual child-process socket blocking, recorded B37C evidence replay,
Java compilation and explicitly MOCKED orchestration are separately reported in
`AUTHORING_CHECKS.json`.

The original B37B website and frozen `~/iris` are not overwritten. The entire
B37 engine is vendored unchanged in `engine/`; `VENDOR_PROVENANCE.json` records
its source archive and every inherited file hash. Native IRIS Stage 3 is reused;
this does NOT run full `SAPipeline.run()`, Stage 4 or posthoc classification.

## Required existing installation

Use the same WSL environment as accepted B37C:

- `~/migration/ntk_stage3_verified_v5_work/.ntk_v5_lora_venv/bin/python`.
- Frozen `~/iris`, matching the existing B33 frozen-state record.
- Local pinned Qwen2.5-Coder-0.5B base and both B33 LoRA adapters.
- Downloads file `batch33_20261018T144300Z_6460a4_result.zip` with the pinned SHA.
- Local CodeQL 2.25.6, Java extractor, the same 16 locked query packs, JDK 21.
- Original pinned OpenGrep 1.25.0 executable.

There is no package installation, pack download, model download or training.
Do not run a B37 GPU scan concurrently. Only one B38 scan is permitted at a time.
The work filesystem must have at least 4 GiB free **before each run**; this is a
minimum check, not a prediction of aggregate A-D storage. Each phase creates its
own database and keeps it locally. Nothing is automatically deleted.

## Four gates

| Phase | Profile | Designed input | Expected acceptance condition |
|---|---|---|---|
| A | CWE-22 | Four path-reading examples | Two positive path files; two controls |
| B | CWE-78 | Four Runtime.exec examples | Two positive command files; two controls |
| C | CWE-79 | Four real JDK HttpHandler implementations | Two unencoded HTML output files; two controls |
| D | All four CWEs | 16 files, including the original four B37 SQL sources | Eight positive files across four CWEs; eight controls; no dropped OpenGrep findings |

All are **intentional development fixtures, not independent gold**. Do not
interpret their result as general accuracy, vulnerability probability, or CVSS.
The expected unit is presence of a CWE-qualified source-to-sink path per file;
it is not the number of raw OpenGrep findings. Additional path variants may exist.

Each phase performs secure ZIP intake, real offline OpenGrep, model/scorer pins,
CodeQL extractor and pack checks, QL compiler checks, trusted Java compilation,
a new real database, compiler API/argument/source extraction, manual CodeQL
diagnostics, native IRIS Stage 3 local inference, strict parsing, semantic
eligibility, new CodeQL paths, evidence fusion and the original V2.2 scorer.

Manual diagnostics NEVER become LLM labels or scored LLM paths. If diagnostics
fail, stop before GPU. If diagnostics work but LoRA predicts `none`, abstains, or
omits a required sink, keep `NEEDS_REVIEW`; never insert the expected label.

## Exact semantic scope

### A: path traversal

Recognizes exact argument zero of selected `java.nio.file.Files.readString`,
`readAllBytes` and `newInputStream` overloads. Actual `System.getenv(String)`
call sites in the current database are declared untrusted by an analyst policy,
not discovered as sources by the model. Explicit JDK transfer models cover
`Path.resolve(String)` and `normalize()`; normalization is NOT declared a
sanitizer. Controls use a fixed path or a choice between fixed allowlisted
filenames. Symlink containment and general sanitization patterns are not proven.

### B: OS commands

Recognizes the command argument zero in exact `Runtime.exec` overloads. An
environment-array or working-directory argument is NOT treated as the command.
The fixture gives the untrusted value control of the executable/command string.
`Runtime.exec` is not assumed to interpret shell metacharacters. No command or
Java application is executed. ProcessBuilder receiver tracking is not supported;
`this` is not silently mapped to an argument. Array overloads are schema-covered
but are not separately demonstrated by these four fixture files.

### C: reflected HTTP/HTML XSS

Uses actual JDK `HttpExchange` and `HttpHandler` APIs, not fake Servlet classes.
Source: direct URI query access through the exchange parameter. Sink: argument
zero of an exact `OutputStream.write` call on the same exchange's response body.
Requires explicit HTML Content-Type, response headers sent before the write,
and the same effectively-final exchange parameter. Only one Content-Type setter
is allowed in the method. Header/send/write ordering uses source ordering in the
same callable; this is a narrow straight-line pattern, NOT a general dominance
or servlet-context proof. Wrappers, aliases of streams, dynamic MIME, multiple
response paths, Spring/JSP, general encoders and stored/DOM XSS are unsupported.

Controls are constant HTML and explicit plain-text output with nosniff. This is
not an evaluation of arbitrary context-sensitive escaping. String conversion
alone is never an XSS sink. Fixtures are compiled and statically analyzed; no
HTTP server or Java handler is started.

### SQL regression

Keeps B35/B37 exact SQL-text semantics. Dynamic `prepareStatement(sql)` is not
blanket-excluded; `setString` binds a value and is withheld from SQL-grammar sink
use. The original V2.2 scorer is unchanged. Positive semantic evidence requires
both an accepted model sink and a matching qualified CodeQL path. Missing paths,
`none` and ABSTAIN remain neutral evidence; original OpenGrep findings remain.

Sources and the additional JDK taint transfers in these profiles are declared
analysis policies, NOT newly learned propagation or source labels. Every finding
records this distinction. The rule set is a review-oriented demo rule set, NOT
the B29 benchmark rules. Scores can differ across CWEs; do not prescribe 85.8 for
all findings. A dataflow path is not proof of practical exploitability.

## Running A-D

From the extracted directory (after checking the archive checksum):

```bash
export NTK_IRIS_PYTHON="$(command -v python)"
bash run.sh --phase A --arm epoch_1
bash run.sh --phase B --arm epoch_1
bash run.sh --phase C --arm epoch_1
bash run.sh --phase D --arm epoch_1
```

Or run the stop-on-error sequence:

```bash
bash run_all.sh epoch_1
```

`run_all.sh` stops immediately for BLOCKED or NEEDS_REVIEW. It does not launch the
website. Re-run only the affected phase after reviewing evidence. Do not change
fixture expectations or bypass gates. `--arm both` runs models sequentially;
first validate epoch_1 to avoid redundant GPU work. The other adapter is retained.

D requires A/B/C receipts for the same arm AND this exact implementation. Receipts
validate stored evidence manifests, not merely a PASS string. All original run
directories must remain available. Editing executable code invalidates receipts.

`--diagnostic-only` performs manual-source/sink CodeQL checks only. It NEVER
creates a model acceptance receipt. It is for fault isolation, not for reporting
four-CWE model success.

## D website

Only after D succeeds:

```bash
bash serve.sh
```

Open `http://127.0.0.1:8766`. B37 remains on 8765 unchanged. The new page accepts
Java ZIPs (16 MiB, 1-24 Java files), selects one or all four profiles, and exposes
only model arms with a valid D receipt. Run the combined sample through the
browser to validate a new web job, not just the CLI receipt.

Each job invokes this real CLI on the uploaded ZIP, creates a new database and
checks input/engine hashes before publishing results. JSON, SARIF, evidence ZIP
and engine log are downloadable. The local server has Host/Origin/CSRF checks;
no CDN or cloud inference. OpenGrep and model subprocesses inherit INET/INET6
socket denial. CodeQL uses local pinned packs with no install/download commands;
this is NOT a claim that the entire CodeQL/JDK toolchain is an OS sandbox.
No Maven/Gradle/project scripts or annotation processors are executed.

Job history is in-memory until shutdown; local artifacts remain under
`batch38_web`. There is no multi-user service, public deployment or production
hardening claim. Keep the server bound to loopback.

## Status and evidence

- `B38_SCOPED_DEMO_COMPLETE`: exact development fixture accepted for requested CWEs
  and arms; can write a phase receipt. Not scientific gold acceptance.
- `B38_COMPLETED_NEEDS_REVIEW`: execution finished, but model-derived results did
  not match fixture expectations; no gate receipt and nonzero exit 3.
- `B38_BLOCKED`: technical or evidence-integrity blocker; exit 2.
- `B38_SCOPED_ANALYSIS_COMPLETE_NOT_A_SAFETY_VERDICT`: an arbitrary supported ZIP
  was analyzed without a known expected outcome; no empty-result safety claim.
- `B38_DIAGNOSTIC_ONLY_COMPLETE_NOT_MODEL_ACCEPTANCE`: manual diagnostics only.

A-D reports go to Downloads, local work to `$W/batch38_runs`. Gates are under
`$W/batch38_gates`. `PROGRESS.json` is finalized to the actual final status, unlike
the stale partial-status file in earlier batches.

Inspect `00_SUMMARY.json`, `UPLOADED_INPUT_PROVENANCE.json`, `DATABASE_PROOF.json`,
`CANDIDATES_BY_CWE.json`, `SOURCES_BY_CWE.json`, `HTTP_CONTEXT_CALLS.json`,
`live/<arm>/native_trace.jsonl`, `analysis/<arm>/cwe-*/SINK_BINDINGS.json`,
`SEMANTIC_DECISIONS.json`, BQRS, CodeQL SARIF, VERIFIED_PATHS and FUSED_FINDINGS.

Database, model caches, inherited B33 evidence, full source workspace and binary
scanner caches remain locally and are listed in EXCLUDED_FILES rather than
needlessly shipped. The evidence ZIP is an audit bundle, not a complete machine
backup. Keep the original run directories. Review local source/log paths before
sharing reports publicly.

## Acceptance after WSL execution

Do not mark all four phases accepted based on CPU tests or a green manual
CodeQL diagnostic. Required: fresh native model observations, qualified real
CodeQL paths for expected positives, no qualifying paths in controls, preserved
OpenGrep findings, input provenance, unchanged frozen repository, valid manifests,
and a new browser upload for the D web gate. Report model misses transparently.
