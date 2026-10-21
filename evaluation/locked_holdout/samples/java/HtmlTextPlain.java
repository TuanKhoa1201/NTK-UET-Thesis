package ntk.b39b7;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
public class HtmlTextPlain {
  public static void handle(HttpExchange exchange) throws IOException {
    String value = exchange.getRequestURI().getQuery();
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
    exchange.sendResponseHeaders(200, 0);
    exchange.getResponseBody().write(value.getBytes(StandardCharsets.UTF_8));
  }
}
