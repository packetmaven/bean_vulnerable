import java.sql.*;

public class VUL002_SQLInjection_PreparedStatement {
    public void vulnerableSearch(String searchTerm) throws SQLException {
        Connection conn = getConnection();
        String sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
        PreparedStatement stmt = conn.prepareStatement(sql);
        ResultSet rs = stmt.executeQuery();
        processResults(rs);
    }
    
    private Connection getConnection() { return null; }
    private void processResults(ResultSet rs) { }
}

