import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServletResponse;

public class SAFE_XSS_EncodeForHtml {
    public void render(HttpServletResponse response, String input) throws Exception {
        String safe = Encode.forHtml(input);
        response.getWriter().print(safe);
    }
}
