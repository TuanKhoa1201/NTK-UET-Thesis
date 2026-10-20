# NTK - Batch 38A failure audit and B38R1 correction

The uploaded run is **BLOCKED before CodeQL and LoRA**. This is a confirmed
scanner startup environment error, not a measured model accuracy problem.

## Verified input

- ZIP SHA-256: `a00a11dd9a727f0456c7c70d275654d24990f06105efdfdbbd6b7d52ee627fda`.
- 12/12 manifest hashes match; 13 ZIP members including the manifest; CRC OK.
- Frozen repository records before and after are equal.
- OpenGrep wrapper installed the inherited IPv4/IPv6 seccomp restriction.
- Scanner failed at startup; no rules result, CodeQL database, or live model result exists in this run.

## Root cause

B38/ntk_b38/scanner.py supplied `XDG_CONFIG_HOME=.../opengrep/.config` without
creating the directory. The official v1.25.0 source checks that variable using
`Sys.is_directory` during initialization. The scanner log records the corresponding
`Sys_error` for the missing `.config`. B37 had created its configuration directory;
this safety precondition was lost in the new B38 scanner wrapper.

B38R1 creates private HOME/XDG/TMP directories, rejects symlinks/non-directories,
checks actual write access before exec, records an environment proof, and retains
the original scanner binary hash, commands/rules, and inherited seccomp wrapper.
No attempt is made to use the real user configuration, install packages, or disable
network isolation to bypass the issue.

## Additional defect found by source review, not by a completed phase D run

The original D scanner coverage gate reused the 16-file per-CWE DATAFLOW test
matrix as the required CALLSITE detection set. It would require a path rule to
report on SQL-only and command-only files. That contract conflates two distinct
stages. B38R1 adds an explicit scanner coverage set derived from the four original
single-CWE fixture groups, including both positive and control files. Each rule
must cover its own four files; unexpected callsites still block known fixtures.

All original 16-per-CWE dataflow tests in phase D remain unchanged. A cross-CWE
false path still fails the model fixture check. Raw scanner findings are not
dropped, and no model label or expected_flow value is edited.

## What the new tests do and do not establish

93 CPU/HTTP/subprocess tests pass. Real directory write probes and child socket
denial are exercised. Fake scanner executables emulate scanner startup and
produce labeled TEST-ONLY results for orchestration checks. CodeQL/GPU orchestration
also has mock tests inherited from B38. These are not new real OpenGrep or model
results. A mandatory on-WSL scanner-only preflight checks A, B, C, SQL and D using
the exact pinned real scanner before any CodeQL/GPU work. A scanner PASS cannot
create a semantic A/B/C/D receipt.

The submitted failed run, this audit, and a future run are distinct. This audit
does not claim successful four-CWE detection or a passed Batch 38A.
