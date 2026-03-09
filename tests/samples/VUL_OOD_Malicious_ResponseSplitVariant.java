import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class VUL_OOD_Malicious_ResponseSplitVariant extends HttpServlet {
    public void vulnerableRedirect(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String url = request.getParameter("redirect");
        response.sendRedirect(url); // Open redirect / response splitting surface
    }

    public void vulnerableHeaderInjection(HttpServletRequest req, HttpServletResponse resp) {
        String userAgent = req.getParameter("userAgent");
        resp.setHeader("X-User-Agent", userAgent); // Untrusted header value
        resp.setHeader("Set-Cookie", "sid=" + req.getParameter("sid")); // CRLF/header injection style sink
    }

    public void vulnerableCookieInjection(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("cookieValue");
        Cookie cookie = new Cookie("userPref", value);
        response.addCookie(cookie);
    }
}
