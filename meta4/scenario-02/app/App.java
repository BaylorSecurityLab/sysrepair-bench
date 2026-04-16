import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

import java.io.OutputStream;
import java.net.InetSocketAddress;

public class App {
    private static final Logger LOG = LogManager.getLogger(App.class);

    public static void main(String[] args) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress(8080), 0);
        s.createContext("/", (HttpExchange ex) -> {
            String q = ex.getRequestURI().getQuery();
            // Populate Thread Context Map from query — the 2021-45046 bypass surface
            if (q != null) ThreadContext.put("q", q);
            LOG.info("request received");
            byte[] body = "ok\n".getBytes();
            ex.sendResponseHeaders(200, body.length);
            OutputStream os = ex.getResponseBody();
            os.write(body); os.close();
            ThreadContext.clearAll();
        });
        s.start();
    }
}
