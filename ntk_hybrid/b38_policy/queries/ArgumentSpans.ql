/** @name NTK B38 exact argument positions
 * @kind table
 * @id java/ntk-b38/argument-spans
 */
import java
import NtkScope
from MethodCall call, Method m, int i
where m = call.getMethod() and ntkRelevant(m) and i >= 0 and i < call.getNumArgument()
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
