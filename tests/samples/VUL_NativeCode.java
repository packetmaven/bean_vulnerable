/**
 * Native Code (JNI) Taint Tracking Test
 * Tests taint propagation through JNI calls
 */
public class VUL_NativeCode {
    
    // Native method declaration
    public native String processNative(String input);
    public native byte[] encryptNative(byte[] data);
    
    // Taint should flow through native calls
    public void processUserData(String userId) {
        // Taint flows into native method
        String result = processNative(userId);
        
        // Result from native method should be tainted
        executeQuery(result);
    }
    
    // Native method with byte array
    public void encryptData(String password) {
        byte[] encrypted = encryptNative(password.getBytes());
        
        // encrypted should be tainted (came from tainted password)
        storeData(encrypted);
    }
    
    // System.loadLibrary - native library loading
    static {
        System.loadLibrary("vulnerable_lib");
    }
    
    private void executeQuery(String sql) {
        // Execute
    }
    
    private void storeData(byte[] data) {
        // Store
    }
}

