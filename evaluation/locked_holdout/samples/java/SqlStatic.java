package ntk.b39b7;
import java.sql.ResultSet;
import java.sql.Statement;
public class SqlStatic {
  public static ResultSet search(Statement statement) throws Exception {
    return statement.executeQuery("SELECT id FROM accounts ORDER BY id");
  }
}
