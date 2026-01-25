package javax.el;

public class ExpressionFactory {
    public static ExpressionFactory newInstance() {
        return new ExpressionFactory();
    }

    public ValueExpression createValueExpression(ELContext context, String expression, Class<?> expectedType) {
        return new ValueExpression();
    }

    public MethodExpression createMethodExpression(ELContext context, String expression, Class<?> expectedType, Class<?>[] paramTypes) {
        return new MethodExpression();
    }
}
