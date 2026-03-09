package com.example.jni;

import javax.servlet.http.HttpServletRequest;

/**
 * Malicious JNI spectrum sample for analysis coverage.
 * This file intentionally demonstrates unsafe JNI usage patterns.
 */
public class JNI_Vuln_Spectrum {
    static {
        System.loadLibrary("jni_vuln_spectrum");
        System.load("/tmp/libjni_vuln_spectrum.dylib");
    }

    public native String nativeReadFile(String path);
    public native int nativeExecute(String command);
    public native String nativeCallbackExec(String command);
    public native String nativeReflectInvoke(String className, String methodName, String arg);

    public String processRequest(HttpServletRequest request) {
        String userPath = request.getParameter("path");
        String userCommand = request.getParameter("cmd");
        String userClass = request.getParameter("klass");
        String userMethod = request.getParameter("method");

        String a = nativeReadFile(userPath);                    // tainted file I/O in native
        int b = nativeExecute(userCommand);                     // tainted command execution in native
        String c = nativeCallbackExec(userCommand);             // native -> Java callback to exec sink
        String d = nativeReflectInvoke(userClass, userMethod, userCommand); // reflection injection

        return a + ":" + b + ":" + c + ":" + d;
    }

    public static String reflectiveSink(String command) {
        try {
            Runtime.getRuntime().exec(command);
        } catch (Exception ignored) {
            // Intentionally ignore in this vulnerable sample.
        }
        return command;
    }
}
