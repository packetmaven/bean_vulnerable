import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class VUL029_XMLDecoder_Deserialization {
    public Object decodeXml(byte[] xmlBytes) {
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlBytes));
        Object obj = decoder.readObject();
        decoder.close();
        return obj;
    }

    public Object decodeXmlStream(InputStream input) {
        XMLDecoder decoder = new XMLDecoder(input);
        Object obj = decoder.readObject();
        decoder.close();
        return obj;
    }
}
