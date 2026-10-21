package ntk.b39b4;
public class CommandShell {
 public static Process launch() throws Exception {
  String command = System.getenv("NTK_SHELL_ARGUMENT");
  return Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
 }
}
