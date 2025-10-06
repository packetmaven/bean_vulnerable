import javax.servlet.http.*;

public class VUL015_SessionFixation extends HttpServlet {
    public void vulnerableLogin(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        if (authenticate(username, password)) {
            HttpSession session = request.getSession(); // Reuses existing session
            session.setAttribute("user", username);
            session.setAttribute("authenticated", true);
        }
    }
    
    public void vulnerableSessionHandling(HttpServletRequest req) {
        HttpSession session = req.getSession(true);
        String sessionId = req.getParameter("sessionId");
        if (sessionId != null) {
            // Vulnerable: accepting session ID from user
            session.setAttribute("customSessionId", sessionId);
        }
    }
    
    private boolean authenticate(String user, String pass) { return true; }
}

