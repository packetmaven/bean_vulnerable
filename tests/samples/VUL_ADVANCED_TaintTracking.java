/**
 * Advanced Taint Tracking Test Case
 * Tests: Implicit Flows, Interprocedural Analysis, Array Element Tracking
 * Research: ACM 2024, TAJ System, FSE 2024
 */
public class VUL_ADVANCED_TaintTracking {
    
    // Test 1: Implicit Flow (Control Dependency)
    public void testImplicitFlow(String password) {
        boolean isAdmin = false;
        if (password.equals("admin123")) {
            isAdmin = true;  // ← Should be tainted via implicit flow!
        }
        System.setProperty("admin.status", String.valueOf(isAdmin));
    }
    
    // Test 2: Interprocedural Analysis
    public void processUserInput(String userId) {
        String query = buildSQLQuery(userId);  // ← Cross-method taint
        executeQuery(query);
    }
    
    private String buildSQLQuery(String id) {
        return "SELECT * FROM users WHERE id=" + id;  // ← id should be tainted here
    }
    
    private void executeQuery(String sql) {
        // Execute
    }
    
    // Test 3: Array Element-Level Tracking
    public void testArrayElements(String taintedInput, String safeInput) {
        String[] data = new String[3];
        data[0] = taintedInput;   // ← Only element 0 is tainted
        data[1] = safeInput;       // ← Element 1 is NOT tainted
        data[2] = "constant";      // ← Element 2 is NOT tainted
        
        // This should be flagged as vulnerable
        executeQuery(data[0]);
        
        // This should be safe
        System.out.println(data[1]);
    }
    
    // Test 4: Collection Element Tracking
    public void testCollections(String userName) {
        java.util.List<String> users = new java.util.ArrayList<>();
        users.add(userName);  // ← userName taints the collection
        users.add("safe");
        
        String first = users.get(0);  // ← Should be tainted
        executeQuery(first);
    }
}

