package ntk.b39b7;
import java.nio.file.Files;
import java.nio.file.Path;
public class PathFixedRead {
  public static String load() throws Exception {
    return Files.readString(Path.of("/srv/ntk/data/help.txt"));
  }
}
