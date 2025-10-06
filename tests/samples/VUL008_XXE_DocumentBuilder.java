import javax.xml.parsers.*;
import org.w3c.dom.Document;
import java.io.StringReader;
import org.xml.sax.InputSource;

public class VUL008_XXE_DocumentBuilder {
    public void vulnerableXMLParsing(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));
        processDocument(doc);
    }
    
    public void vulnerableXMLProcessing(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xml)));
    }
    
    private void processDocument(Document doc) { }
}

