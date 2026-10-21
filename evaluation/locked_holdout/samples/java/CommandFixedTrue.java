package ntk.b39b7;
public class CommandFixedTrue {
  public static Process launch() throws Exception {
    return Runtime.getRuntime().exec("/usr/bin/true");
  }
}
