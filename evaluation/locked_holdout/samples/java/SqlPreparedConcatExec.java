package ntk.b39b7;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
public class SqlPreparedConcatExec {
  public static ResultSet search(Connection connection) throws Exception {
    String name = System.getenv("NTK_H7_SQL_B");
    PreparedStatement ps = connection.prepareStatement("SELECT id FROM accounts WHERE name='" + name + "'");
    return ps.executeQuery();
  }
}
