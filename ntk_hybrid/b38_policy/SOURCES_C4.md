# Primary references and evidence boundary

Existing project evidence: C3 diagnostic ZIP SHA-256
`ecddecbe1a08a9ad0e125d2cdc752ce0ea9d6af2dad457630bbf01d80ac01af6`.
It recorded four paths, including one through the reviewed literal HTML-text
encoder. This kit contains a limited read-only regression subset with provenance.

External design references (checked 19 October 2026):

- OWASP XSS Prevention Cheat Sheet: output encoding must match HTML text, quoted
  ordinary attribute and other contexts; HTML encoding is not a general script/
  URL/CSS encoding solution.
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- Oracle JDK 21 Trees API: compiler elements, tree paths and source positions.
  https://docs.oracle.com/en/java/javase/21/docs/api/jdk.compiler/com/sun/source/util/Trees.html
- Oracle JDK 21 String API: literal CharSequence replacement versus regex methods.
  https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/String.html

These references motivate the narrow implementation. They do not validate this
new NTK implementation, certify the fixtures, or constitute an independent benchmark.
