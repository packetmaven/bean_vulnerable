/**
 * Context-Sensitive Taint Analysis Test
 * Tests k-CFA (Tai-e v0.5.1)
 */
public class VUL_ContextSensitive {
    
    // Same method buildQuery() called from TWO different contexts
    public void processUser(String userId) {
        String query = buildQuery(userId);  // Context 1: processUser -> buildQuery
        executeQuery(query);
    }
    
    public void processAdmin(String adminId) {
        String query = buildQuery(adminId);  // Context 2: processAdmin -> buildQuery
        executeSecureQuery(query);
    }
    
    // This method should have TWO distinct contexts tracked
    private String buildQuery(String id) {
        return "SELECT * FROM table WHERE id=" + id;
    }
    
    private void executeQuery(String sql) {
        // Vulnerable execution
    }
    
    private void executeSecureQuery(String sql) {
        // Secure execution
    }
}

