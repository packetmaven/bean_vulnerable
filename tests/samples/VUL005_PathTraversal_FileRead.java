import java.io.*;

public class VUL005_PathTraversal_FileRead {
    public String vulnerableFileRead(String filename) throws IOException {
        File file = new File("/var/www/uploads/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        return reader.readLine();
    }
    
    public void vulnerableFileAccess(String path) throws IOException {
        FileInputStream fis = new FileInputStream("./data/" + path);
        fis.read();
    }
}

