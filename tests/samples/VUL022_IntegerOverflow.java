public class VUL022_IntegerOverflow {
    public void vulnerableArrayAllocation(int size) {
        if (size > 0) {
            int arraySize = size * 4; // Potential overflow
            byte[] buffer = new byte[arraySize];
            processBuffer(buffer);
        }
    }
    
    public void vulnerableMoneyCalculation(int price, int quantity) {
        int total = price * quantity; // Overflow possible
        if (total < 0) {
            // Negative total due to overflow
            System.out.println("Free items due to overflow!");
        }
        processPayment(total);
    }
    
    public void vulnerableBufferSize(int userInput) {
        int bufferSize = userInput + 1024; // Addition overflow
        if (bufferSize > 0) {
            allocateBuffer(bufferSize);
        }
    }
    
    private void processBuffer(byte[] buffer) { }
    private void processPayment(int amount) { }
    private void allocateBuffer(int size) { }
}

