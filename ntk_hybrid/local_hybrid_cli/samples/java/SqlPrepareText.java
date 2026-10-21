package ntk.b39b4;
import java.sql.*;
public class SqlPrepareText {
 public static PreparedStatement prepare(Connection connection) throws Exception {
  String name = System.getenv("NTK_PREPARE_TEXT");
  return connection.prepareStatement("SELECT id FROM accounts WHERE name='" + name + "'");
 }
}
