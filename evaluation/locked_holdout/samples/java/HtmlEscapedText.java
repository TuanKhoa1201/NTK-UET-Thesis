package ntk.b39b7;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
public class HtmlEscapedText {
  static String esc(String s) {
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
  }
  public static void handle(HttpExchange exchange) throws IOException {
    String value = exchange.getRequestURI().getQuery();
    String body = "<p>" + esc(value) + "</p>";
    exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
    exchange.sendResponseHeaders(200, 0);
    exchange.getResponseBody().write(body.getBytes(StandardCharsets.UTF_8));
  }
}
