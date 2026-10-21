package ntk.b39b4;
import java.nio.file.*;
public class PathDownload {
 public static byte[] load() throws Exception {
  String name = System.getenv("NTK_DOWNLOAD_PATH");
  return Files.readAllBytes(Path.of(name));
 }
}
