package ntk.b39b7;
public class CommandDataArgument {
  public static Process launch() throws Exception {
    String value = System.getenv("NTK_H7_CMD_D");
    return Runtime.getRuntime().exec(new String[]{"/usr/bin/printf", "%s", value});
  }
}
