import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class VUL030_JNDI_LookupInjection {
    public Object lookupResource(String jndiName) throws NamingException {
        Context ctx = new InitialContext();
        return ctx.lookup(jndiName);
    }

    public Object lookupWithEnv(String jndiName, String providerUrl) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, providerUrl);
        Context ctx = new InitialContext(env);
        return ctx.lookup(jndiName);
    }
}
