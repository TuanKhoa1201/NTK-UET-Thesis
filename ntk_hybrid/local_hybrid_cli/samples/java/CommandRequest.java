package ntk.b39b4;
public class CommandRequest {
 public static Process launch() throws Exception {
  String command = System.getenv("NTK_COMMAND");
  return Runtime.getRuntime().exec(command);
 }
}
