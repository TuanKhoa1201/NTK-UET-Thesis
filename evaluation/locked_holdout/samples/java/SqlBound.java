package ntk.b39b7;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
public class SqlBound {
  public static ResultSet search(Connection connection) throws Exception {
    String name = System.getenv("NTK_H7_SQL_D");
    PreparedStatement ps = connection.prepareStatement("SELECT id FROM accounts WHERE name=?");
    ps.setString(1, name);
    return ps.executeQuery();
  }
}
