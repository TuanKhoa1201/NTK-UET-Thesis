package ntk.b39b7;
import java.nio.file.Files;
import java.nio.file.Path;
public class PathRootChecked {
  public static String load() throws Exception {
    String name = System.getenv("NTK_H7_PATH_D");
    Path root = Path.of("/srv/ntk/data").toAbsolutePath().normalize();
    Path candidate = root.resolve(name).normalize();
    if (!candidate.startsWith(root)) throw new SecurityException("outside root");
    return Files.readString(candidate);
  }
}
