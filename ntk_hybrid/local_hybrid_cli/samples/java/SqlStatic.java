package ntk.b39b4;
import java.sql.*;
public class SqlStatic {
 public static ResultSet search(Statement statement) throws Exception {
  return statement.executeQuery("SELECT id FROM accounts");
 }
}
