import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class VUL026_ZipSlip_ArchiveExtraction {
    public void extractZip(InputStream zipStream, File destDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(zipStream);
        ZipEntry entry;
        byte[] buffer = new byte[1024];
        while ((entry = zis.getNextEntry()) != null) {
            File outFile = new File(destDir, entry.getName());
            FileOutputStream fos = new FileOutputStream(outFile);
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
            zis.closeEntry();
        }
        zis.close();
    }
}
