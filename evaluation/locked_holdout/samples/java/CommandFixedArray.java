package ntk.b39b7;
public class CommandFixedArray {
  public static Process launch() throws Exception {
    return Runtime.getRuntime().exec(new String[]{"/usr/bin/printf", "static"});
  }
}
