package ntk.b39b7;
public class CommandShellSh {
  public static Process launch() throws Exception {
    String command = System.getenv("NTK_H7_CMD_A");
    return Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
  }
}
