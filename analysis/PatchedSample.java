public class VUL001_SQLInjection_Basic {
    public void vulnerableLogin(String username, String password) {
        username = username.replace("'", "''");
password = password.replace("'", "''");
String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
executeQuery(query);
    }
    
    private void executeQuery(String sql) {
        System.out.println("Executing: " + sql);
    }
}

