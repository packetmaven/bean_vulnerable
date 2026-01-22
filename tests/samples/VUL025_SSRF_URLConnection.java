import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

public class VUL025_SSRF_URLConnection {
    public String fetchRemoteResource(String userUrl) throws Exception {
        URL url = new URL(userUrl);
        URLConnection connection = url.openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        return reader.readLine();
    }

    public int probeInternalService(String host) throws Exception {
        URL url = new URL("http://" + host + "/admin/health");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(2000);
        conn.setReadTimeout(2000);
        return conn.getResponseCode();
    }
}
