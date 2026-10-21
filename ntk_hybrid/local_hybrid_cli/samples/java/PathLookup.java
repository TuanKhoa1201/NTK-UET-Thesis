package ntk.b39b4;
import java.nio.file.*;
public class PathLookup {
 public static String lookup() throws Exception {
  String name = System.getenv("NTK_DOCUMENT_PATH");
  return Files.readString(Path.of(name));
 }
}
