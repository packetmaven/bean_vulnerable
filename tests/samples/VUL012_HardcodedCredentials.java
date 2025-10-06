import java.sql.*;

public class VUL012_HardcodedCredentials {
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";
    
    public Connection vulnerableDatabaseConnection() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/mydb";
        String username = "root";
        String password = "password123";
        return DriverManager.getConnection(url, username, password);
    }
    
    public void vulnerableAPICall() {
        String secretKey = "hardcoded-secret-key-2023";
        makeAPIRequest(secretKey);
    }
    
    private void makeAPIRequest(String key) { }
}

