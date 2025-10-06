import javax.servlet.http.*;
import java.io.IOException;

public class VUL018_HTTPResponseSplitting extends HttpServlet {
    public void vulnerableRedirect(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        String url = request.getParameter("redirect");
        response.sendRedirect(url); // No validation
    }
    
    public void vulnerableHeaderInjection(HttpServletRequest req, HttpServletResponse resp) {
        String userAgent = req.getParameter("userAgent");
        resp.setHeader("X-User-Agent", userAgent); // No sanitization
    }
    
    public void vulnerableCookieInjection(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("cookieValue");
        Cookie cookie = new Cookie("userPref", value);
        response.addCookie(cookie);
    }
}

