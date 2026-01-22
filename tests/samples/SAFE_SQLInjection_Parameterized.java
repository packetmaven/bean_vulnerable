import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SAFE_SQLInjection_Parameterized {
    public void safeSearch(String searchTerm) throws SQLException {
        Connection conn = getConnection();
        String sql = "SELECT * FROM products WHERE name LIKE ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, "%" + searchTerm + "%");
        ResultSet rs = stmt.executeQuery();
        processResults(rs);
    }

    private Connection getConnection() { return null; }
    private void processResults(ResultSet rs) { }
}
