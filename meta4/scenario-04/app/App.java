import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class App {
    private static final Logger LOG = LogManager.getLogger(App.class);
    public static void main(String[] args) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress(8080), 0);
        s.createContext("/", (HttpExchange ex) -> {
            LOG.info("hit: {}", ex.getRequestURI().getQuery());
            byte[] body = "ok\n".getBytes();
            ex.sendResponseHeaders(200, body.length);
            OutputStream os = ex.getResponseBody();
            os.write(body); os.close();
        });
        s.start();
    }
}
