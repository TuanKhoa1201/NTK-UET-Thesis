package ntk.b39b7;
import java.sql.ResultSet;
import java.sql.Statement;
public class SqlFormatted {
  public static ResultSet search(Statement statement) throws Exception {
    String name = System.getenv("NTK_H7_SQL_C");
    String sql = String.format("SELECT id FROM accounts WHERE name='%s'", name);
    return statement.executeQuery(sql);
  }
}
