package ntk.b39b7;
import java.sql.ResultSet;
import java.sql.Statement;
public class SqlFixedChoice {
  public static ResultSet search(Statement statement) throws Exception {
    String order = System.getenv("NTK_H7_SQL_E");
    String sql = "name".equals(order)
        ? "SELECT id FROM accounts ORDER BY name"
        : "SELECT id FROM accounts ORDER BY id";
    return statement.executeQuery(sql);
  }
}
