import java.util.HashMap;

public class VUL_DashboardMetrics {
    static class Profile {
        String name;
        String email;
        Meta meta;
    }

    static class Meta {
        String note;
    }

    // Local sanitizer stub to make the sample compile without external deps.
    static class StringEscapeUtils {
        static String escapeHtml4(String input) {
            if (input == null) {
                return "";
            }
            return input.replace("<", "&lt;").replace(">", "&gt;");
        }
    }

    public void handle(String userInput) {
        Profile profile = new Profile();
        profile.name = userInput; // tainted field

        Meta meta = new Meta();
        meta.note = userInput; // tainted field
        profile.meta = meta;

        String raw = userInput;
        String alias = raw;
        String derived = alias + profile.name;
        String safe = StringEscapeUtils.escapeHtml4(derived);

        HashMap map = new HashMap();
        map.put("safe", safe);

        String fieldCopy = profile.name;
        if (fieldCopy != null) {
            System.out.println(fieldCopy);
        }
    }
}
