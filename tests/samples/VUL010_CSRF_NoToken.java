import javax.servlet.http.*;
import java.io.IOException;

public class VUL010_CSRF_NoToken extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        String action = request.getParameter("action");
        String amount = request.getParameter("amount");
        String account = request.getParameter("account");
        
        if ("transfer".equals(action)) {
            performMoneyTransfer(account, amount);
        }
    }
    
    public void vulnerablePasswordChange(HttpServletRequest req) {
        String newPassword = req.getParameter("newPassword");
        changeUserPassword(getCurrentUser(req), newPassword);
    }
    
    private void performMoneyTransfer(String account, String amount) { }
    private void changeUserPassword(String user, String password) { }
    private String getCurrentUser(HttpServletRequest req) { return "user"; }
}

