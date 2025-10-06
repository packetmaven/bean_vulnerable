public class VUL013_BufferOverflow_Array {
    public void vulnerableArrayAccess(int index, String[] data) {
        String[] buffer = new String[10];
        buffer[index] = data[0]; // No bounds checking
        processBuffer(buffer);
    }
    
    public void vulnerableStringBuffer(String input) {
        char[] buffer = new char[100];
        for (int i = 0; i < input.length(); i++) {
            buffer[i] = input.charAt(i); // No length validation
        }
    }
    
    public void vulnerableMemoryCopy(byte[] source, byte[] dest) {
        System.arraycopy(source, 0, dest, 0, source.length); // No size check
    }
    
    private void processBuffer(String[] buffer) { }
}

