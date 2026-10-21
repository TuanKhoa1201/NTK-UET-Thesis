package ntk.b39b7;
import java.nio.file.Files;
import java.nio.file.Path;
public class PathResolveUnsafe {
  public static String load() throws Exception {
    String name = System.getenv("NTK_H7_PATH_C");
    Path root = Path.of("/srv/ntk/data");
    return Files.readString(root.resolve(name));
  }
}
