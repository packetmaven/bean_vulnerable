package javax.servlet.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;

public interface HttpServletRequest {
    String getParameter(String name);
    String getHeader(String name);
    String getQueryString();
    Cookie[] getCookies();
    BufferedReader getReader() throws IOException;
    InputStream getInputStream() throws IOException;
}
