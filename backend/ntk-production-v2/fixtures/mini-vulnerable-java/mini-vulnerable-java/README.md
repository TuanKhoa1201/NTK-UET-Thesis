# mini-vulnerable-java

A small, self-contained Maven/Java 17 project containing **nine
intentionally vulnerable code patterns**, each isolated in its own
class and paired with a safe alternative. It exists purely as a
**test fixture** for exercising a SAST pipeline (OpenGrep/Semgrep Java
rules, IRIS data-flow analysis, and LLM-assisted triage) end to end.

> ⚠️ **Do not deploy this code. Do not copy patterns from it into real
> software.** Every "vulnerable" method exists solely to be detected.

## Why this project exists

Static analysis pipelines need a small, fast, dependency-light corpus
with **known ground truth** to validate that:

1. OpenGrep/Semgrep rules actually fire on realistic Java call
   patterns (not just contrived one-liners).
2. IRIS (or any data-flow/taint engine) can trace source → sink
   across method boundaries.
3. An LLM-based triage step correctly distinguishes the vulnerable
   method from the adjacent safe method in the same file, i.e. it
   isn't just pattern-matching on class/file names.

## Project structure

```
mini-vulnerable-java/
├── pom.xml
├── README.md
└── src/
    └── main/
        └── java/
            └── com/example/vulnerable/
                ├── Main.java                     (CLI entry point, wires inputs to sinks)
                ├── CommandInjection.java          CWE-78
                ├── PathTraversal.java             CWE-22
                ├── SqlInjection.java              CWE-89
                ├── SsrfExample.java                CWE-918
                ├── HardcodedPassword.java          CWE-798
                ├── WeakHash.java                    CWE-328
                ├── XxeExample.java                  CWE-611
                ├── InsecureDeserialization.java     CWE-502
                ├── LdapInjection.java               CWE-90
                └── HashUtil.java                   (shared helper for the "safe" variants; not vulnerable)
```

**Size:** 10 source files, ~430 lines of code total.

## Build & run

```bash
mvn compile
# or, to produce a jar:
mvn package
java -cp target/classes com.example.vulnerable.Main ping "8.8.8.8"
```

The project has **zero external dependencies** — everything used
(`java.sql`, `javax.naming`, `javax.xml.parsers`, `java.security`,
`java.net`, `java.io`) ships with the JDK, so it builds fully offline
once Maven's own plugins are cached.

## Convention used in every vulnerable class

Every class follows the same shape so tooling and reviewers can
compare patterns consistently:

- A `// TAINT SOURCE` comment marks where external/untrusted input
  enters (standing in for `request.getParameter(...)`, a request
  body, an uploaded file, a cookie, etc.).
- A `// SINK` comment marks the dangerous API call.
- A `xxxVulnerable(...)` method contains the flaw.
- A `xxxSafe(...)` method sits right next to it in the same file,
  showing the recommended fix, so a triage tool must reason about
  *how* the input is used, not just *that* a dangerous API appears
  somewhere in the file.

## Vulnerabilities included

### 1. CWE-78 — OS Command Injection
**File:** `CommandInjection.java` — `pingHostVulnerable`

A "ping this host" diagnostic feature concatenates a caller-supplied
hostname into a shell command string and executes it via
`/bin/sh -c`. Input such as `8.8.8.8; cat /etc/passwd` or
`` `whoami` `` breaks out of the intended command.

**Safe version:** `pingHostSafe` validates the hostname against a
strict regex and uses `ProcessBuilder` with a discrete argument array
(no shell, no string concatenation of a command line).

**Expected OpenGrep finding:** rules in the
`java.lang.security.audit.command-injection` / semgrep
`java-runtime-exec` family, matching `Runtime.getRuntime().exec(...)`
or `ProcessBuilder("/bin/sh", "-c", ...)` fed by a tainted,
concatenated string.

---

### 2. CWE-22 — Path Traversal
**File:** `PathTraversal.java` — `readAttachmentVulnerable`

A "download attachment" feature builds a file path by concatenating
a fixed upload directory with a caller-supplied filename, with no
normalization or containment check. Input like
`../../../../etc/passwd` escapes the intended directory.

**Safe version:** `readAttachmentSafe` rejects path separators/`..`
outright, resolves against the canonical base directory, and
verifies the resulting path is still contained within it.

**Expected OpenGrep finding:** `java.lang.security.audit.path-traversal`
/ semgrep `java-path-traversal-*`, matching
`new File(baseDir, tainted)` → `Files.readAllBytes(...)` with no
sanitization in between.

---

### 3. CWE-89 — SQL Injection
**File:** `SqlInjection.java` — `findUserVulnerable`

A "find user by username" lookup concatenates the username directly
into SQL text executed via a plain `Statement`. Input like
`' OR '1'='1` or `'; DROP TABLE users; --` changes the query's logic.

**Safe version:** `findUserSafe` uses a parameterized
`PreparedStatement` with `setString(...)`, so input is always treated
as data.

**Expected OpenGrep finding:**
`java.lang.security.audit.sqli.jdbc-sqli` / semgrep
`java-sqli-statement`, matching `Statement.executeQuery(String)` where
the argument is built via `+` concatenation of a tainted variable.
The `PreparedStatement` version should produce **no finding** — a
useful negative control for the pipeline.

---

### 4. CWE-918 — Server-Side Request Forgery (SSRF)
**File:** `SsrfExample.java` — `fetchRemoteResourceVulnerable`

A "fetch remote resource" feature (e.g. avatar-from-URL, webhook
preview) opens an outbound HTTP connection to a URL taken verbatim
from the caller. An attacker can target internal-only endpoints
(cloud metadata service, internal admin panels, `localhost` services)
that are otherwise unreachable from outside the network.

**Safe version:** `fetchRemoteResourceSafe` restricts the scheme to
`https`, validates the host against a strict allow-list, and disables
automatic redirect following (to prevent allow-list bypass via
redirect).

**Expected OpenGrep finding:**
`java.lang.security.audit.ssrf` / semgrep `java-net-url-ssrf`,
matching `new URL(tainted).openConnection()` reachable from external
input with no destination validation.

---

### 5. CWE-798 — Use of Hard-coded Credentials
**File:** `HardcodedPassword.java`

An admin-console login check and an internal API client both embed
real-looking secrets (`ADMIN_PASSWORD`, `INTERNAL_API_KEY`) as string
literals directly in source code.

**Safe version:** `loginToAdminConsoleSafe` reads credentials from
the environment at runtime and fails closed if they are absent,
comparing a hash rather than a plaintext secret.

**Expected OpenGrep finding:** semgrep's generic secrets rules
(`generic.secrets.security.detected-generic-secret`) plus Java-specific
`hardcoded-password-*` rules, matching a `String` literal assigned to
a `static final` field whose name matches `password|secret|api[_-]?key|token`.

---

### 6. CWE-328 — Use of a Broken/Risky Cryptographic Hash (MD5)
**File:** `WeakHash.java` — `hashPasswordVulnerable`

A "create account" flow hashes a new password with unsalted MD5, an
algorithm that is fast to compute and vulnerable to collision and
rainbow-table attacks — unsuitable for password storage.

**Safe version:** `hashPasswordSafe` demonstrates the salting +
iteration principle (dependency-free stand-in for a real KDF); the
README/comments explicitly call out that a production system should
use bcrypt/scrypt/Argon2 instead.

**Expected OpenGrep finding:**
`java.lang.security.audit.crypto.weak-hash-algorithm` / semgrep
`insecure-hash-algorithm-md5`, matching
`MessageDigest.getInstance("MD5")` (also fires for `"SHA1"`/`"SHA-1"`
in most rule packs).

---

### 7. CWE-611 — XML External Entity (XXE) Injection
**File:** `XxeExample.java` — `parseContactsXmlVulnerable`

An "import contacts from XML" feature parses caller-supplied XML with
a `DocumentBuilderFactory` left at its default (insecure) settings,
which permit `DOCTYPE` declarations and external entity resolution —
enabling local file disclosure or SSRF via `SYSTEM` entities.

**Safe version:** `parseContactsXmlSafe` disables `DOCTYPE`
declarations outright (`disallow-doctype-decl`) and, as defense in
depth, disables external general/parameter entities and XInclude,
per the OWASP XXE Prevention Cheat Sheet.

**Expected OpenGrep finding:**
`java.lang.security.audit.xxe` / semgrep `java-xxe-*`, matching
`DocumentBuilderFactory.newInstance()` used to parse untrusted input
without the `disallow-doctype-decl` feature being set.

---

### 8. CWE-502 — Deserialization of Untrusted Data
**File:** `InsecureDeserialization.java` — `restoreSessionVulnerable`

A "restore session from cookie" feature calls
`ObjectInputStream.readObject()` on bytes that come entirely from the
client, with no filtering. Any dangerous "gadget" class reachable on
the classpath can be leveraged for remote code execution without the
attacker ever needing to construct a legitimate object.

**Safe version:** `restoreSessionSafe` installs a JEP 290
`ObjectInputFilter` that allow-lists only the expected class and
bounds array size, rejecting everything else.

**Expected OpenGrep finding:**
`java.lang.security.audit.object-deserialization` / semgrep
`java-deserialization-*`, matching `new ObjectInputStream(...)` /
`.readObject()` on a tainted stream with no `setObjectInputFilter`
call in the same method.

---

### 9. CWE-90 — LDAP Injection
**File:** `LdapInjection.java` — `findEmployeeVulnerable`

A corporate directory "look up employee by username" feature
concatenates the username directly into an LDAP search filter.
Input like `admin)(|(uid=*` alters the filter's logical structure.

**Safe version:** `findEmployeeSafe` escapes `\ * ( ) NUL` per
RFC 4515 before embedding the value in the filter.

**Expected OpenGrep finding:**
`java.lang.security.audit.ldap-injection` / semgrep
`java-ldap-injection`, matching `DirContext.search(...)` where the
filter argument is built via concatenation of a tainted variable with
no escaping function applied.

## Expected OpenGrep run

```bash
opengrep --config p/java scan src/main/java
# or, with the security-audit ruleset specifically:
opengrep --config p/security-audit scan src/main/java
```

Expected outcome: **9 findings**, one per `*Vulnerable` method above,
each pointing at the file/line of the annotated `// SINK` comment.
The corresponding `*Safe` methods in the same files are the negative
controls — a well-tuned rule set (and a well-tuned IRIS/LLM triage
step) should **not** flag them, which is what makes this fixture
useful for measuring false-positive rate as well as recall.

## Notes for IRIS / data-flow analysis

Each vulnerable method keeps source and sink in the **same method**
(no interprocedural hop) to make first-pass detection reliable, while
`Main.java` adds one additional call-graph hop from `args[]` into each
class's public entry point — useful for testing whether the
data-flow engine can follow taint across a class boundary, not just
within a single method body.

## License / usage

For academic and internal security-tooling evaluation only.
