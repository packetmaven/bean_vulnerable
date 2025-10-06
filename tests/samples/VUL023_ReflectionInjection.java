import java.lang.reflect.*;

public class VUL023_ReflectionInjection {
    public void vulnerableClassLoading(String className) throws Exception {
        Class<?> clazz = Class.forName(className); // User-controlled class name
        Object instance = clazz.newInstance();
        processObject(instance);
    }
    
    public void vulnerableMethodInvocation(String methodName, Object target) throws Exception {
        Class<?> clazz = target.getClass();
        Method method = clazz.getMethod(methodName); // User-controlled method
        method.invoke(target);
    }
    
    public void vulnerableFieldAccess(String fieldName, Object obj) throws Exception {
        Class<?> clazz = obj.getClass();
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object value = field.get(obj);
        processValue(value);
    }
    
    private void processObject(Object obj) { }
    private void processValue(Object value) { }
}

