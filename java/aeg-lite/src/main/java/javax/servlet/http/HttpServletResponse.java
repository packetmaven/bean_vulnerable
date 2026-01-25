package javax.servlet.http;

import java.io.IOException;
import java.io.PrintWriter;

public interface HttpServletResponse {
    PrintWriter getWriter() throws IOException;
    void sendRedirect(String location) throws IOException;
    void setHeader(String name, String value);
    void addHeader(String name, String value);
    void setStatus(int sc);
    void addCookie(Cookie cookie);
}
