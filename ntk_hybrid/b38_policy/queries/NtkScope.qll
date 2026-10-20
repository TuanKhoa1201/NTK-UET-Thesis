/** Narrow JDK profiles. These are explicit analysis models, not LLM outputs. */
import java
import semmle.code.java.dataflow.DataFlow

predicate ntkRelevant(Method m) {
  (m.getDeclaringType().getPackage().getName() = "java.sql" and
   m.getName() = ["execute", "executeQuery", "prepareStatement", "setString"])
  or (m.getDeclaringType().hasQualifiedName("java.lang", "System") and m.getName() = "getenv")
  or (m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and m.getName() = "exec")
  or (m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and m.getName() = "start")
  or (m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      m.getName() = ["readString", "readAllBytes", "newInputStream"])
  or (m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
      m.getName() = ["resolve", "normalize"])
  or (m.getDeclaringType().hasQualifiedName("java.io", "OutputStream") and m.getName() = "write")
  or (m.getDeclaringType().hasQualifiedName("java.net", "URI") and m.getName() = ["getRawQuery", "getQuery"])
  or (m.getDeclaringType().hasQualifiedName("com.sun.net.httpserver", "HttpExchange") and
      m.getName() = ["getRequestURI", "getResponseBody"])
}

predicate ntkExchangeReceiver(MethodCall m, Parameter p) {
  p.isEffectivelyFinal() and
  p.getType().(RefType).hasQualifiedName("com.sun.net.httpserver", "HttpExchange") and
  m.getEnclosingCallable() = p.getCallable() and
  DataFlow::localFlow(DataFlow::parameterNode(p), DataFlow::exprNode(m.getQualifier()))
}

predicate ntkHttpSource(MethodCall query, Parameter exchange) {
  query.getMethod().getDeclaringType().hasQualifiedName("java.net", "URI") and
  query.getMethod().getSignature() = ["getRawQuery()", "getQuery()"] and
  exists(MethodCall request |
    query.getQualifier() = request and
    request.getMethod().getDeclaringType().hasQualifiedName("com.sun.net.httpserver", "HttpExchange") and
    request.getMethod().getSignature() = "getRequestURI()" and
    ntkExchangeReceiver(request, exchange)
  )
}

predicate ntkContentType(MethodCall set, Parameter exchange) {
  set.getMethod().getDeclaringType().hasQualifiedName("com.sun.net.httpserver", "Headers") and
  set.getMethod().getName() = ["set", "add"] and
  set.getArgument(0).(StringLiteral).getValue().toLowerCase() = "content-type" and
  exists(MethodCall headers |
    set.getQualifier() = headers and
    headers.getMethod().getDeclaringType().hasQualifiedName("com.sun.net.httpserver", "HttpExchange") and
    headers.getMethod().getSignature() = "getResponseHeaders()" and
    ntkExchangeReceiver(headers, exchange)
  )
}

predicate ntkHtmlWrite(MethodCall write, Parameter exchange) {
  write.getMethod().getDeclaringType().hasQualifiedName("java.io", "OutputStream") and
  write.getMethod().getSignature() = ["write(byte[])", "write(byte[],int,int)"] and
  exists(MethodCall response, MethodCall header, MethodCall send |
    write.getQualifier() = response and
    response.getMethod().getDeclaringType().hasQualifiedName("com.sun.net.httpserver", "HttpExchange") and
    response.getMethod().getSignature() = "getResponseBody()" and
    ntkExchangeReceiver(response, exchange) and
    ntkContentType(header, exchange) and
    (header.getArgument(1).(StringLiteral).getValue().toLowerCase() = "text/html" or
     header.getArgument(1).(StringLiteral).getValue().toLowerCase().matches("text/html;%")) and
    not exists(MethodCall other | ntkContentType(other, exchange) and other != header) and
    send.getMethod().getDeclaringType().hasQualifiedName("com.sun.net.httpserver", "HttpExchange") and
    send.getMethod().getSignature() = "sendResponseHeaders(int,long)" and
    ntkExchangeReceiver(send, exchange) and
    header.getEnclosingCallable() = write.getEnclosingCallable() and
    send.getEnclosingCallable() = write.getEnclosingCallable() and
    header.getLocation().getEndLine() < send.getLocation().getStartLine() and
    send.getLocation().getEndLine() < write.getLocation().getStartLine()
  )
}

predicate ntkSource(MethodCall call, string cwe) {
  (cwe = ["22", "78", "89"] and
   call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "System") and
   call.getMethod().getSignature() = "getenv(java.lang.String)")
  or (cwe = "79" and exists(Parameter p | ntkHttpSource(call, p)))
}

predicate ntkSinkContext(MethodCall call, string cwe) {
  cwe = ["22", "78", "89"]
  or (cwe = "79" and exists(Parameter p | ntkHtmlWrite(call, p)))
}

predicate ntkSameHttpExchange(Expr src, Expr snk) {
  exists(MethodCall source, MethodCall write, Parameter p |
    src = source and snk = write.getArgument(0) and
    ntkHttpSource(source, p) and ntkHtmlWrite(write, p)
  )
}

predicate ntkAdditionalTransfer(DataFlow::Node a, DataFlow::Node b, string cwe) {
  exists(MethodCall m |
    b.asExpr() = m and (
      (cwe = "22" and
        m.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
        ((m.getMethod().getSignature() = "resolve(java.lang.String)" and
          (a.asExpr() = m.getQualifier() or a.asExpr() = m.getArgument(0))) or
         (m.getMethod().getSignature() = "normalize()" and a.asExpr() = m.getQualifier())))
      or (cwe = "22" and
        m.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
        m.getMethod().getSignature() = "get(java.lang.String,java.lang.String[])" and
        a.asExpr() = m.getArgument(0))
      or (cwe = "79" and
        m.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
        m.getMethod().getSignature() = ["getBytes()", "getBytes(java.nio.charset.Charset)"] and
        a.asExpr() = m.getQualifier())
      or (cwe = "79" and
        m.getMethod().getDeclaringType().hasQualifiedName("java.net", "URLDecoder") and
        m.getMethod().getSignature() = "decode(java.lang.String,java.nio.charset.Charset)" and
        a.asExpr() = m.getArgument(0))
    )
  )
}
