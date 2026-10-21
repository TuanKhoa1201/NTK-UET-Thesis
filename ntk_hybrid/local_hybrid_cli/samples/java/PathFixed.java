package ntk.b39b4;
import java.nio.file.*;
public class PathFixed {
 public static String load() throws Exception {
  return Files.readString(Path.of("/opt/ntk/config.txt"));
 }
}
