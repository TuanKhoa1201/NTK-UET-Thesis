package ntk.b39b4;
import java.sql.*;
public class SqlBoundValue {
 public static ResultSet search(Connection connection) throws Exception {
  String name = System.getenv("NTK_BOUND_VALUE");
  PreparedStatement prepared = connection.prepareStatement("SELECT id FROM accounts WHERE name=?");
  prepared.setString(1, name);
  return prepared.executeQuery();
 }
}
