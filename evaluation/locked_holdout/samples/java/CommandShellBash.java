package ntk.b39b7;
public class CommandShellBash {
  public static Process launch() throws Exception {
    String command = System.getenv("NTK_H7_CMD_B");
    return Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", command});
  }
}
