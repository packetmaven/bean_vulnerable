import javax.el.*;

public class VUL024_ExpressionLanguageInjection {
    public void vulnerableELEvaluation(String userExpression) {
        ExpressionFactory factory = ExpressionFactory.newInstance();
        ELContext context = new StandardELContext(factory);
        ValueExpression expr = factory.createValueExpression(context, userExpression, Object.class);
        Object result = expr.getValue(context);
        processResult(result);
    }
    
    public void vulnerableTemplateProcessing(String template, String userInput) {
        String expression = "${" + userInput + "}";
        ExpressionFactory ef = ExpressionFactory.newInstance();
        ELContext elContext = new StandardELContext(ef);
        ValueExpression ve = ef.createValueExpression(elContext, expression, String.class);
        String result = (String) ve.getValue(elContext);
        renderTemplate(result);
    }
    
    private void processResult(Object result) { }
    private void renderTemplate(String content) { }
}

