/**
 * @name NTK B37A exact argument spans
 * @description Compiler-derived spans for joining SQL arguments to CodeQL path results.
 * @id ntk/b37a/argument-spans
 */
import java
from MethodCall call, Method m, int i
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
  i >= 0 and i < call.getNumArgument()
select
  call.getLocation().getFile().getRelativePath() as uri,
  call.getLocation().getStartLine() as call_line,
  call.getLocation().getStartColumn() as call_column,
  i as argument_index,
  call.getArgument(i).getLocation().getStartLine() as start_line,
  call.getArgument(i).getLocation().getStartColumn() as start_column,
  call.getArgument(i).getLocation().getEndLine() as end_line,
  call.getArgument(i).getLocation().getEndColumn() as end_column,
  m.getDeclaringType().getPackage().getName() as package,
  m.getDeclaringType().getName() as clazz,
  m.getName() as method,
  m.getSignature() as compiler_signature
