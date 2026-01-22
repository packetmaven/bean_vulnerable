import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class VUL027_XPath_Injection {
    public boolean authenticate(InputStream xml, String user, String pass) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(xml);

        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "/users/user[@name='" + user + "' and @pass='" + pass + "']";
        XPathExpression compiled = xpath.compile(expr);
        return (Boolean) compiled.evaluate(doc, XPathConstants.BOOLEAN);
    }

    public String lookupEmail(InputStream xml, String uid) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "/users/user[@uid='" + uid + "']/email/text()";
        return (String) xpath.evaluate(expr, doc, XPathConstants.STRING);
    }
}
