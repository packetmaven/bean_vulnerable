import java.io.IOException;

public class VUL004_CommandInjection_ProcessBuilder {
    public void vulnerableFileOperation(String userInput) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ls -la " + userInput);
        Process process = pb.start();
    }
    
    public void vulnerableNetworkCommand(String target) throws IOException {
        String[] cmd = {"nslookup", target};
        ProcessBuilder builder = new ProcessBuilder(cmd);
        builder.start();
    }
}

