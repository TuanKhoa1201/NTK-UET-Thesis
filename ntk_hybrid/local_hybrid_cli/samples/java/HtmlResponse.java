package ntk.b39b4;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
public class HtmlResponse {
 public static void handle(HttpExchange exchange) throws IOException {
  String value = exchange.getRequestURI().getRawQuery();
  String body = "<p>" + value + "</p>";
  exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
  exchange.sendResponseHeaders(200, 0);
  exchange.getResponseBody().write(body.getBytes(StandardCharsets.UTF_8));
 }
}
