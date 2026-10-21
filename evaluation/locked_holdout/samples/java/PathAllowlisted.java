package ntk.b39b7;
import java.nio.file.Files;
import java.nio.file.Path;
public class PathAllowlisted {
  public static String load() throws Exception {
    String name = System.getenv("NTK_H7_PATH_E");
    if (name == null || !name.matches("[A-Za-z0-9_-]+\\.txt")) throw new SecurityException("bad name");
    Path root = Path.of("/srv/ntk/data");
    return Files.readString(root.resolve(name));
  }
}
