import java.util.Map;

public class VUL021_NullPointerDereference {
    public void vulnerableMapAccess(Map<String, String> userMap, String key) {
        String value = userMap.get(key);
        int length = value.length(); // Potential NPE
        processValue(value.toUpperCase());
    }
    
    public void vulnerableArrayAccess(String[] array, int index) {
        String element = array[index];
        if (element.startsWith("admin")) { // No null check
            grantAccess();
        }
    }
    
    public void vulnerableObjectChaining(User user) {
        String email = user.getProfile().getEmail().toLowerCase(); // Chain without null checks
        sendNotification(email);
    }
    
    private void processValue(String value) { }
    private void grantAccess() { }
    private void sendNotification(String email) { }
    
    class User {
        Profile getProfile() { return null; }
    }
    
    class Profile {
        String getEmail() { return null; }
    }
}

