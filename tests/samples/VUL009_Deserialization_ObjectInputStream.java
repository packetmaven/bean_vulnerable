import java.io.*;

public class VUL009_Deserialization_ObjectInputStream {
    public Object vulnerableDeserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
    
    public void vulnerableObjectProcessing(InputStream input) throws Exception {
        ObjectInputStream objStream = new ObjectInputStream(input);
        Object obj = objStream.readObject();
        processObject(obj);
    }
    
    private void processObject(Object obj) { }
}

