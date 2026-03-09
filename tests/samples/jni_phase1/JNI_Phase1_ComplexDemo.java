package com.example.jni;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class JNI_Phase1_ComplexDemo {
  static {
    System.loadLibrary("phase1demo");
    System.load("/opt/native/libphase1demo.so");
  }

  private final Map<String, String> cache = new HashMap<>();
  private String lastNativeValue;

  public native String nativeEcho(String input);
  public native int nativeLookup(String userId, String query);
  public native byte[] nativeDigest(byte[] data, int mode);
  public static native void nativeSetField(Target target, String value);
  public native String nativeTransform(String data, String path);

  public String process(String userInput, String query, byte[] data, String path) {
    String echo = nativeEcho(userInput);
    int result = nativeLookup(userInput, query);
    byte[] digest = nativeDigest(data, 2);
    nativeSetField(new Target(), query);
    String transform = nativeTransform(query, path);
    cache.put("lastEcho", echo);
    lastNativeValue = transform;
    return echo + ":" + result + ":" + transform + ":" + digest.length;
  }

  public String processFromRequest(String request, String url) {
    String payload = request + ":" + url;
    String echoed = nativeEcho(payload);
    cache.put("requestEcho", echoed);
    return echoed;
  }

  public void syncToNative(String input, String file) {
    byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
    nativeDigest(bytes, 1);
    nativeTransform(input, file);
  }

  public static class Target {
    public String value;
  }
}
