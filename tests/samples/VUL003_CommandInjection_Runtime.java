import java.io.IOException;

public class VUL003_CommandInjection_Runtime {
    public void vulnerablePing(String host) throws IOException {
        String command = "ping -c 4 " + host;
        Runtime.getRuntime().exec(command);
    }
    
    public void vulnerableSystemCall(String filename) throws IOException {
        Process proc = Runtime.getRuntime().exec("cat " + filename);
        proc.waitFor();
    }
}

