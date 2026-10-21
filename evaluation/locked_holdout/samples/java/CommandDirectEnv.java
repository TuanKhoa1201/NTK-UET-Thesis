package ntk.b39b7;
public class CommandDirectEnv {
  public static Process launch() throws Exception {
    String command = System.getenv("NTK_H7_CMD_C");
    return Runtime.getRuntime().exec(command);
  }
}
