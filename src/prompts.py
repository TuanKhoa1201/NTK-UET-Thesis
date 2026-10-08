API_LABELLING_SYSTEM_PROMPT = """\
You are a security expert. \
You are given a list of APIs to be labeled as potential taint sources, sinks, or APIs that propagate taints. \
Taint sources are values that an attacker can use for unauthorized and malicious operations when interacting with the system. \
Taint source APIs usually return strings or custom object types. Setter methods are typically NOT taint sources. \
Taint sinks are program points that can use tainted data in an unsafe way, which directly exposes vulnerability under attack. \
Taint propagators carry tainted information from input to the output without sanitization, and typically have non-primitive input and outputs. \
Return the result as a json list with each object in the format:

{ "package": <package name>,
  "class": <class name>,
  "method": <method name>,
  "signature": <signature of the method>,
  "sink_args": <list of arguments or `this`; empty if the API is not sink>,
  "type": <"source", "sink", or "taint-propagator"> }

DO NOT OUTPUT ANYTHING OTHER THAN JSON.\
"""

API_LABELLING_USER_PROMPT = """\
{cwe_long_description}

Some example source/sink/taint-propagator methods are:
{cwe_examples}

Among the following methods, \
assuming that the arguments passed to the given function is malicious, \
what are the functions that are potential source, sink, or taint-propagators to {cwe_description} attack (CWE-{cwe_id})?

Package,Class,Method,Signature
{methods}
"""

FUNC_PARAM_LABELLING_SYSTEM_PROMPT = """\
You are a security expert. \
You are given a list of APIs implemented in a Java project, and you need to identify which function \
parameters could carry malicious, attacker-controlled end-user input.

There are TWO cases where a parameter should be treated as tainted:

1. Library case: functions that could be invoked by a downstream library/package with untrusted input \
(e.g. deserializers, parsers). Utility functions unrelated to the library's primary purpose should be ignored.

2. Web-application entry-point case: if a method signature contains web-framework annotations such as \
@RequestParam, @PathVariable, @RequestBody, @RequestHeader, @CookieValue, @ModelAttribute (Spring), \
@QueryParam, @PathParam, @FormParam, @HeaderParam (JAX-RS), or similar, the annotated parameter(s) \
ALWAYS come directly from the HTTP request and MUST be treated as tainted, regardless of whether \
the project looks like a reusable library. Do NOT exclude these just because the method looks like \
a "final" HTTP handler - for web applications, request handlers are exactly where the untrusted input enters the program.

Return the result as a json list with each object in the format:

{ "package": <package name>,
  "class": <class name>,
  "method": <method name>,
  "signature": <signature>,
  "tainted_input": <a list of argument names that are potentially tainted> }

In the result list, only keep the functions that have at least one potentially tainted parameter \
(either via downstream library usage, or via web-framework annotations as described above). \
Do not output anything other than JSON.\
"""

FUNC_PARAM_LABELLING_USER_PROMPT = """\
You are analyzing the Java project {project_username}/{project_name}. \
Here is the project summary:

{project_readme_summary}

Please look at the following public methods in the project and their documentations (if present). \
Identify which methods have parameters that are tainted, either because:
a) the method could be invoked by a downstream package with malicious end-user input, or
b) the method signature contains a web-framework annotation (@RequestParam, @PathVariable, @RequestBody, \
@RequestHeader, @CookieValue, @QueryParam, @PathParam, @FormParam, @HeaderParam, etc.) marking a parameter \
as coming directly from an HTTP request.

Utility functions unrelated to handling external input should be ignored. \
Do not return an empty list just because the project is an application rather than a library - \
case (b) above applies to applications too.

Package,Class,Method,Signature,Doc
{methods}
"""

POSTHOC_FILTER_SYSTEM_PROMPT = """\
You are an expert in detecting security vulnerabilities. \
You are given the starting point (source) and the ending point (sink) of a dataflow path in a Java project that may be a potential vulnerability. \
Analyze the given taint source and sink and predict whether the given dataflow can be part of a vulnerability or not, and store it as a boolean in "is_vulnerable". \
Note that, the source must be either a) the formal parameter of a public library function which might be invoked by a downstream package, or b) the result of a function call that returns tainted input from end-user. \
If the given source or sink do not satisfy the above criteria, mark the result as NOT VULNERABLE. \
Please provide a very short explanation associated with the verdict. \
Assume that the intermediate path has no sanitizer.

Return all four fields exactly once.
The explanation must be one short sentence of at most 40 words.
Do not repeat any sentence or phrase.

Answer in JSON object with the following format:

{ "source_is_false_positive": <true or false>,
  "sink_is_false_positive": <true or false>,
  "is_vulnerable": <true or false>,
  "explanation": <ONE SHORT SENTENCE> }

Do not include anything else in the response.\
"""

POSTHOC_FILTER_USER_PROMPT = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```\
"""

POSTHOC_FILTER_USER_PROMPT_W_CONTEXT = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```

{context}\
"""
# The key should be the CWE number without any string prefixes.
# The value should be sentences describing more specific details for detecting the CWE.
POSTHOC_FILTER_HINTS = {
    "022": "Note: please be careful about defensing against absolute paths and \"..\" paths. Just canonicalizing paths might not be sufficient for the defense.",
    "078": "Note that other than typical Runtime.exec which is directly executing command, using Java Reflection to create dynamic objects with unsanitized inputs might also cause OS Command injection vulnerability. This includes deserializing objects from untrusted strings and similar functionalities. Writing to config files about library data may also induce unwanted execution of OS commands.",
    "079": "Please be careful about reading possibly tainted HTML input. During sanitization, do not assume the sanitization to be sufficient.",
    "094": "Please note that dubious error messages can sometimes be handled by downstream code for execution, resulting in CWE-094 vulnerability. Injection of malicious values might lead to arbitrary code execution as well.",
    "089": "Please be careful about reading possibly tainted SQL input. Look for SQL queries that are constructed using string concatenation or similar methods without proper sanitization.",
    "918": "Server-Side Request Forgery occurs when untrusted input controls the target of an outgoing HTTP or other protocol request. Watch for user input flowing into URL constructors, HTTP client execute/connect methods, or SSRF-related libraries without validation.",
    "502": "Be cautious of calls to deserialization methods like `readObject()` or `deserialize()` when passed data from untrusted sources. Attackers may craft malicious object graphs or gadget chains to trigger unexpected behavior or even remote code execution. Check if class allowlisting or validation is in place. Avoid deserializing directly from network input or unvalidated byte arrays.",
    "807": "Pay special attention to cases where user-controlled input is directly used in permission checks (e.g., permission strings or resource identifiers). Focus on whether permission checks (such as Subject.isPermitted or similar APIs) rely on tainted or untrusted data, which may allow privilege escalation or unauthorized access.",
    "352": "Check if the JSONP callback parameter is validated or restricted. Unchecked callback parameters may allow attackers to inject arbitrary JavaScript, leading to CSRF or data theft.",
    "611": "Check if a default entity resolver is enabled, and if there is a Document Type Definition (DTD). The DTD may include arbitrary HTTP requests that the server may execute. Be careful with deserialization of XML-derived objects.",
    "295": "If certificate pinning is being used, ensure that all relevant properties of the certificate are fully validated before the certificate is pinned, including the hostname. Always verify the full certificate chain."
}

SNIPPET_CONTEXT_SIZE = 4
