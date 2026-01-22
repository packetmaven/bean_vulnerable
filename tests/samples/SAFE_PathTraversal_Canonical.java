import java.io.File;

public class SAFE_PathTraversal_Canonical {
    public File resolve(String baseDir, String userPath) throws Exception {
        File base = new File(baseDir);
        File target = new File(base, userPath);
        String canonical = target.getCanonicalPath();
        return new File(canonical);
    }
}
