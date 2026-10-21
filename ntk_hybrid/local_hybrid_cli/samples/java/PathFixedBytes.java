package ntk.b39b4;
import java.nio.file.*;
public class PathFixedBytes {
 public static byte[] load() throws Exception {
  return Files.readAllBytes(Path.of("/opt/ntk/help.txt"));
 }
}
