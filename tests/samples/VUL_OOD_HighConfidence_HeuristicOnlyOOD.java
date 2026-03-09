import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;
import javax.crypto.Cipher;
import javax.el.ELContext;
import javax.el.ExpressionFactory;
import javax.el.StandardELContext;
import javax.el.ValueExpression;
import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class VUL_OOD_HighConfidence_HeuristicOnlyOOD extends HttpServlet {
    private int balance = 100000;
    private int count = 0;
    private String authState = "guest";
    private final Repository userRepository = new Repository();

    private native long nativePivot(byte[] blob, String cmd);

    static {
        try {
            System.loadLibrary("ood_native_bridge");
        } catch (Throwable ignored) {
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            executePolyglotAttackSurface(request, response);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void executePolyglotAttackSurface(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userName = request.getParameter("user");
        String pin = request.getParameter("pin");
        String cmd = request.getParameter("cmd");
        String fileName = request.getParameter("file");
        String xmlBlob = request.getParameter("xml");
        String endpoint = request.getParameter("endpoint");
        String className = request.getParameter("className");
        String methodName = request.getParameter("methodName");
        String scriptPayload = request.getParameter("script");

        // SQL injection (string concatenation + execute)
        Connection conn = openConnection();
        Statement statement = conn.createStatement();
        String sql = "SELECT * FROM accounts WHERE username='" + userName + "' AND pin='" + pin + "'";
        statement.execute(sql);

        // Command injection (runtime + process builder + method handles)
        Runtime.getRuntime().exec(cmd);
        new ProcessBuilder("/bin/sh", "-c", cmd).start();
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            MethodHandle mh = lookup.findVirtual(Runtime.class, "exec", MethodType.methodType(Process.class, String.class));
            mh.invoke(Runtime.getRuntime(), request.getParameter("mhCmd"));
        } catch (Throwable ignored) {
        }

        // Path traversal
        FileInputStream fis = new FileInputStream("/var/data/" + fileName);
        FileReader fr = new FileReader("/opt/uploads/" + fileName);

        // XSS and log injection
        response.getWriter().println("<div>" + request.getParameter("xss") + "</div>");
        System.out.println("User " + userName + " action=" + request.getParameter("action"));

        // LDAP injection
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        InitialDirContext dir = new InitialDirContext(env);
        String ldapQuery = "(uid=" + request.getParameter("uid") + ")";
        dir.search("dc=example,dc=com", ldapQuery, new SearchControls());

        // XXE + XPath injection
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xmlBlob)));

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        String xpathExpr = "//user[@id='" + request.getParameter("id") + "']";
        xpath.compile(xpathExpr).evaluate(doc);

        // EL injection
        ExpressionFactory ef = ExpressionFactory.newInstance();
        ELContext elContext = new StandardELContext(ef);
        String expression = "${" + request.getParameter("expr") + "}";
        ValueExpression valueExpression = ef.createValueExpression(elContext, expression, Object.class);
        Object elResult = valueExpression.getValue(elContext);

        // Script engine injection
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        Object scriptResult = engine.eval(scriptPayload);

        // Reflection injection
        Class<?> dynamicClass = Class.forName(className);
        Method dynamicMethod = dynamicClass.getMethod(methodName, String.class);
        dynamicMethod.invoke(this, request.getParameter("arg"));

        // SSRF
        URL target = new URL(endpoint);
        HttpURLConnection httpConn = (HttpURLConnection) target.openConnection();
        InputStream remote = httpConn.getInputStream();

        // Unsafe deserialization
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object payload = ois.readObject();

        // Weak crypto + insecure randomness + hardcoded credentials
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(request.getParameter("seed").getBytes());
        Cipher c = Cipher.getInstance("DES");
        Random weakRandom = new Random();
        int otp = weakRandom.nextInt();
        String password = "password123";
        String API_KEY = "sk-demo-hardcoded";

        // Integer overflow + buffer issues
        int quantity = Integer.parseInt(request.getParameter("qty"));
        int unitPrice = Integer.parseInt(request.getParameter("price"));
        int tax = Integer.parseInt(request.getParameter("tax"));
        int total = quantity * unitPrice * tax;
        int[] payloadArray = new int[quantity * unitPrice + tax];

        char[] buffer = request.getParameter("xss").toCharArray();
        int index = Integer.parseInt(request.getParameter("index"));
        char observed = buffer[index];
        String sampleText = request.getParameter("sample");
        for (int i = 0; i < sampleText.length(); i++) {
            sampleText.charAt(i);
        }

        // Null dereference chain
        String lowered = userRepository.getProfile().getEmail().toLowerCase();

        // HTTP response splitting
        response.setHeader("X-Trace", request.getParameter("hdr"));
        response.addHeader("Location", request.getParameter("redir"));

        // Session fixation + trust boundary violation + state-changing operations
        boolean authenticated = authenticate(userName, password);
        if (authenticated) {
            HttpSession session = request.getSession();
            session.setAttribute("role", request.getParameter("role"));
            authState = "auth";
            grantAdminAccess(request.getParameter("targetUser"));
            changePassword(request.getParameter("newPassword"));
            performMoneyTransfer(request.getParameter("to"), request.getParameter("amount"));
        }

        // Race condition
        if (balance > 0) {
            Thread.sleep(1);
            balance -= Integer.parseInt(request.getParameter("amount"));
            count++;
        }

        // Additional trust sink
        Properties props = new Properties();
        props.setProperty("runtime.role", request.getParameter("role"));
        System.setProperty("auth.user", request.getParameter("user"));

        // JNI + dynamic payload pivot
        if (payload != null) {
            nativePivot(payload.toString().getBytes(), cmd);
        }

        // Keep local variables alive
        if (elResult != null || scriptResult != null || remote != null || fis != null || fr != null || c != null) {
            response.getWriter().write("done:" + total + ":" + otp + ":" + observed + ":" + lowered + ":" + payloadArray.length);
        }
    }

    private Connection openConnection() throws Exception {
        return DriverManager.getConnection("jdbc:h2:mem:test");
    }

    private boolean authenticate(String user, String password) {
        return user != null && password != null;
    }

    private void grantAdminAccess(String targetUser) {
        authState = "admin:" + targetUser;
    }

    private void changePassword(String newPassword) {
        authState = "pw:" + newPassword;
    }

    private void performMoneyTransfer(String to, String amount) {
        authState = "tx:" + to + ":" + amount;
    }

    static class Repository {
        Profile getProfile() {
            return null;
        }
    }

    static class Profile {
        String getEmail() {
            return null;
        }
    }
}
