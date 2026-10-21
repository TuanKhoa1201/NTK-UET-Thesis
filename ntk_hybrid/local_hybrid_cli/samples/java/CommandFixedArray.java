package ntk.b39b4;
public class CommandFixedArray {
 public static Process launch() throws Exception {
  return Runtime.getRuntime().exec(new String[]{"/usr/bin/printf", "static"});
 }
}
