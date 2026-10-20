/**
 * @name NTK B37A compiler-resolved external method calls
 * @description Extract callsites and exact callable identities from the new Java database.
 * @id ntk/b37a/api-calls
 */
import java
from MethodCall call, Method m, string static_flag
where
  m = call.getMethod() and
  (
    (m.getDeclaringType().getPackage().getName() = "java.sql" and
      (m.getName() = "execute" or m.getName() = "executeQuery" or
       m.getName() = "prepareStatement" or m.getName() = "setString"))
    or
    (m.getDeclaringType().hasQualifiedName("java.lang", "System") and
      m.getName() = "getenv")
  ) and
  (
    (m.isStatic() and static_flag = "true") or
    (not m.isStatic() and static_flag = "false")
  )
select
  call.getLocation().getFile().getRelativePath() as uri,
  call.getLocation().getStartLine() as start_line,
  call.getLocation().getStartColumn() as start_column,
  call.getLocation().getEndLine() as end_line,
  call.getLocation().getEndColumn() as end_column,
  m.getDeclaringType().getPackage().getName() as package,
  m.getDeclaringType().getName() as clazz,
  m.getName() as method,
  m.getSignature() as compiler_signature,
  m.getStringSignature() as short_signature,
  m.getReturnType().getName() as return_type,
  m.getNumberOfParameters() as arity,
  static_flag as is_static
