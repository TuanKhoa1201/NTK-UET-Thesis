# Persistent localhost workbench

Local HTTP UI for uploading JDK-only project ZIPs, running the exact four-arm hybrid backend, retaining verified history and exporting JSON/SARIF. It runs separately from the original scoped production web.

The original self-contained backend source archive is retained as backend_b39b4.zip because setup_workbench.py checks its pinned content SHA. This historical internal filename is required for compatibility; it is not a new GitHub release title.

Default UI mode is read-only. Scans require an explicit --enable-scan and a local operator confirmation. Do not publicly expose or reverse-proxy localhost 8767 without independent security hardening. This is a local research workbench, not a hardened multi-user deployment.

The WSL startup uses previously installed local models, packages and pinned evidence. Repository checkout alone is not enough to reproduce those assets.

**Provenance:** code is preserved from verified local experiment packages. Keep existing internal module names, pinned hashes and release metadata intact; new public directory names describe functionality rather than experiment IDs.
