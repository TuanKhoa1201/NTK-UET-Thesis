package ntk.b39b7;
import java.sql.ResultSet;
import java.sql.Statement;
public class SqlStatementConcat {
  public static ResultSet search(Statement statement) throws Exception {
    String name = System.getenv("NTK_H7_SQL_A");
    return statement.executeQuery("SELECT id FROM accounts WHERE name='" + name + "'");
  }
}
