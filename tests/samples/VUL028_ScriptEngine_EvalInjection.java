import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class VUL028_ScriptEngine_EvalInjection {
    public Object evalUserExpression(String expression) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        return engine.eval(expression);
    }

    public Object evalTemplate(String template, String userInput) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        String script = "var input = '" + userInput + "'; " + template;
        return engine.eval(script);
    }
}
