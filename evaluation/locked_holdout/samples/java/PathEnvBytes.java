package ntk.b39b7;
import java.nio.file.Files;
import java.nio.file.Path;
public class PathEnvBytes {
  public static byte[] load() throws Exception {
    String name = System.getenv("NTK_H7_PATH_B");
    return Files.readAllBytes(Path.of(name));
  }
}
