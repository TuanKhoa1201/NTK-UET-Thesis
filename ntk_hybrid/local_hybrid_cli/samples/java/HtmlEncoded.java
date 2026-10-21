package ntk.b39b4;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
public class HtmlEncoded {
 public static String encode(String value) {
  return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
 }
 public static void handle(HttpExchange exchange) throws IOException {
  String value = exchange.getRequestURI().getRawQuery();
  String body = "<p>" + encode(value) + "</p>";
  exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
  exchange.sendResponseHeaders(200, 0);
  exchange.getResponseBody().write(body.getBytes(StandardCharsets.UTF_8));
 }
}
