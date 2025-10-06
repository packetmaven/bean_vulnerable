public class VUL014_RaceCondition_SharedResource {
    private int balance = 1000;
    private boolean isLoggedIn = false;
    
    public void vulnerableWithdraw(int amount) {
        if (balance >= amount) {
            // Race condition: balance can be modified here
            Thread.yield(); // Simulate delay
            balance -= amount;
            System.out.println("Withdrawn: " + amount);
        }
    }
    
    public void vulnerableLogin(String username, String password) {
        if (authenticate(username, password)) {
            // Race condition: multiple threads can set this
            isLoggedIn = true;
            grantAccess();
        }
    }
    
    private boolean authenticate(String user, String pass) { return true; }
    private void grantAccess() { }
}

