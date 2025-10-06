import java.io.*;
import java.sql.*;

public class VUL020_ResourceLeak {
    public void vulnerableFileHandling(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename);
        BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
        String line = reader.readLine();
        // Resources not closed - memory leak
        processData(line);
    }
    
    public void vulnerableDatabaseConnection() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users");
        // Connection, statement, and result set not closed
        while (rs.next()) {
            processRow(rs);
        }
    }
    
    public void vulnerableStreamHandling(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = input.read(buffer)) != -1) {
            output.write(buffer, 0, bytesRead);
        }
        // Streams not closed
    }
    
    private void processData(String data) { }
    private void processRow(ResultSet rs) { }
}

