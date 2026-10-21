package ntk.b39b4;
public class CommandFixed {
 public static Process launch() throws Exception {
  return Runtime.getRuntime().exec("/usr/bin/true");
 }
}
