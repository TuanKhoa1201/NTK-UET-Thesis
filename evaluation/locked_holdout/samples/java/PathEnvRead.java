package ntk.b39b7;
import java.nio.file.Files;
import java.nio.file.Path;
public class PathEnvRead {
  public static String load() throws Exception {
    String name = System.getenv("NTK_H7_PATH_A");
    return Files.readString(Path.of(name));
  }
}
