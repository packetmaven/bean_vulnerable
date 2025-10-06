import java.util.logging.Logger;

public class VUL017_LogInjection {
    private static final Logger logger = Logger.getLogger(VUL017_LogInjection.class.getName());
    
    public void vulnerableLoginAttempt(String username) {
        logger.info("Login attempt for user: " + username);
    }
    
    public void vulnerableErrorLogging(String userInput, String error) {
        System.out.println("Error processing request from " + userInput + ": " + error);
        logger.severe("User " + userInput + " caused error: " + error);
    }
    
    public void vulnerableAuditLog(String action, String user) {
        String logEntry = "User " + user + " performed action: " + action;
        writeToAuditLog(logEntry);
    }
    
    private void writeToAuditLog(String entry) { }
}

