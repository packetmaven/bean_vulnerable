import javax.servlet.http.*;

public class VUL019_TrustBoundaryViolation extends HttpServlet {
    public void vulnerableDataFlow(HttpServletRequest request) {
        String userInput = request.getParameter("data");
        // Directly using user input in trusted context
        System.setProperty("app.config", userInput);
    }
    
    public void vulnerablePrivilegeEscalation(HttpServletRequest req) {
        String role = req.getParameter("role");
        HttpSession session = req.getSession();
        // Trusting user-provided role without validation
        session.setAttribute("userRole", role);
        if ("admin".equals(role)) {
            grantAdminAccess();
        }
    }
    
    public void vulnerableFileSystemAccess(String userPath) {
        // Using user input to access file system
        java.io.File file = new java.io.File("/secure/data/" + userPath);
        if (file.exists()) {
            processSecureFile(file);
        }
    }
    
    private void grantAdminAccess() { }
    private void processSecureFile(java.io.File file) { }
}

