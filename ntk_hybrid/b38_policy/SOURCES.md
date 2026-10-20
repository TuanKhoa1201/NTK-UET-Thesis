# Primary references used for scope design

These documents explain API semantics; they do NOT certify the new queries or
model results. No large passages from these references are copied into the code.

- Oracle JDK 21 HttpExchange: request URI, response headers and response body lifecycle.
  https://docs.oracle.com/en/java/javase/21/docs/api/jdk.httpserver/com/sun/net/httpserver/HttpExchange.html
- Oracle JDK HTTP server package: real HttpHandler/HttpExchange abstractions.
  https://docs.oracle.com/en/java/javase/21/docs/api/jdk.httpserver/com/sun/net/httpserver/package-summary.html
- CodeQL Java/Kotlin dataflow: ConfigSig, Global taint tracking, additional flow steps.
  https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-java/
- OWASP Path Traversal: containment and untrusted path input.
  https://owasp.org/www-community/attacks/Path_Traversal
- OWASP OS Command Injection Defense: command/argument distinction; Runtime.exec does not implicitly invoke a shell.
  https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- OWASP XSS Prevention: output context and encoding must be distinguished.
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

Project basis: accepted B37B engine bundle and B37C recorded evidence. See
VENDOR_PROVENANCE.json and tests/evidence37c/REFERENCE_MANIFEST.json.
