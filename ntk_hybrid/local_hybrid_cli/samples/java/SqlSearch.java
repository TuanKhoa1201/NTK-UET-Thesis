package ntk.b39b4;
import java.sql.*;
public class SqlSearch {
 public static ResultSet search(Statement statement) throws Exception {
  String name = System.getenv("NTK_ACCOUNT");
  return statement.executeQuery("SELECT id FROM accounts WHERE name='" + name + "'");
 }
}
