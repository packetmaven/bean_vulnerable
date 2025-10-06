/**
 * Path-Sensitive Taint Analysis Test
 * Tests symbolic execution and path feasibility
 */
public class VUL_PathSensitive {
    
    // Path 1: If input is sanitized, safe query
    // Path 2: If input is NOT sanitized, vulnerable query
    public void processWithValidation(String userInput, boolean validated) {
        String query;
        
        if (validated) {
            // Path 1: SAFE path (validated)
            query = "SELECT * FROM safe WHERE id=" + sanitize(userInput);
            executeQuery(query);  // Should be SAFE on this path
        } else {
            // Path 2: VULNERABLE path (not validated)
            query = "SELECT * FROM vuln WHERE id=" + userInput;
            executeQuery(query);  // Should be VULNERABLE on this path
        }
    }
    
    // Multiple branching paths
    public void complexBranching(String input) {
        String data;
        
        if (input != null) {
            if (input.length() > 0) {
                // Path: not-null AND length > 0
                data = input.toUpperCase();
                executeQuery(data);  // Tainted on this specific path
            } else {
                // Path: not-null BUT length == 0
                data = "default";
                executeQuery(data);  // Safe on this path
            }
        } else {
            // Path: null
            data = "empty";  // Safe path
        }
    }
    
    private String sanitize(String s) {
        return s.replaceAll("[^a-zA-Z0-9]", "");
    }
    
    private void executeQuery(String sql) {
        // Execute
    }
}

