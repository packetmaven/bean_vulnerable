import java.util.Random;

public class VUL016_InsecureRandomness {
    public String vulnerableTokenGeneration() {
        Random random = new Random(); // Predictable seed
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            token.append(random.nextInt(10));
        }
        return token.toString();
    }
    
    public String vulnerablePasswordReset() {
        Random rand = new Random(System.currentTimeMillis()); // Predictable seed
        return "reset_" + rand.nextLong();
    }
    
    public int vulnerableSessionId() {
        Random r = new Random(12345); // Fixed seed
        return r.nextInt(1000000);
    }
}

