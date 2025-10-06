import javax.servlet.http.*;
import java.io.IOException;

public class VUL006_XSS_ServletResponse extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        String userInput = request.getParameter("message");
        response.getWriter().println("<html><body>");
        response.getWriter().println("Hello " + userInput);
        response.getWriter().println("</body></html>");
    }
    
    public void vulnerableEcho(String input, HttpServletResponse resp) throws IOException {
        resp.getWriter().write("<script>alert('" + input + "')</script>");
    }
}

