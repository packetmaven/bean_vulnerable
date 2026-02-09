import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * RealVuln_001_SQLInjection
 *
 * Intentionally vulnerable example for security research / detector regression.
 *
 * Vulnerability:
 * - CWE-89 SQL Injection
 * - Untrusted data from HttpServletRequest is concatenated into a SQL query.
 *
 * Notes:
 * - This file is used by `prepare_training_data.py` and CLI regressions.
 * - The goal is to have a "realistic" sample that yields a non-trivial CPG.
 */
public class RealVuln_001_SQLInjection {

    // Simulate a data source (intentionally hard-coded for sample)
    private static final String JDBC_URL = "jdbc:sqlite::memory:";

    public void handle(HttpServletRequest request, HttpServletResponse response) {
        String user = request.getParameter("user");
        String sort = request.getParameter("sort"); // also untrusted
        String limit = request.getParameter("limit"); // also untrusted

        // Naive normalization that does NOT prevent SQL injection
        user = user == null ? "" : user.trim();
        sort = sort == null ? "id" : sort.trim();
        limit = limit == null ? "10" : limit.trim();

        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            conn = DriverManager.getConnection(JDBC_URL);
            stmt = conn.createStatement();

            // ------------------------------------------------------------
            // VULNERABLE: user-controlled string concatenation in SQL query
            // ------------------------------------------------------------
            String query =
                    "SELECT id, username, role FROM users "
                            + "WHERE username = '"
                            + user
                            + "' "
                            + "ORDER BY "
                            + sort
                            + " LIMIT "
                            + limit;

            rs = stmt.executeQuery(query);
            while (rs.next()) {
                // "Use" results (not important for the sample)
                String username = rs.getString("username");
                String role = rs.getString("role");
                writeLine(response, "user=" + username + ", role=" + role);
            }
        } catch (SQLException e) {
            writeLine(response, "DB error: " + e.getMessage());
        } finally {
            closeQuietly(rs);
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    private static void writeLine(HttpServletResponse response, String msg) {
        try {
            response.getWriter().println(msg);
        } catch (Exception ignored) {
            // ignored for sample
        }
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c == null) return;
        try {
            c.close();
        } catch (Exception ignored) {
            // ignored for sample
        }
    }
}