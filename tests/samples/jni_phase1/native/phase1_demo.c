#include <jni.h>
#include <string.h>

JNIEXPORT jstring JNICALL Java_com_example_jni_JNI_1Phase1_1ComplexDemo_nativeEcho(
    JNIEnv *env, jobject obj, jstring input) {
  const char *chars = (*env)->GetStringUTFChars(env, input, 0);
  if (!chars) {
    return 0;
  }
  (*env)->ReleaseStringUTFChars(env, input, chars);
  return input;
}

JNIEXPORT jint JNICALL Java_com_example_jni_JNI_1Phase1_1ComplexDemo_nativeLookup(
    JNIEnv *env, jobject obj, jstring userId, jstring query) {
  const char *user = (*env)->GetStringUTFChars(env, userId, 0);
  const char *q = (*env)->GetStringUTFChars(env, query, 0);
  jint result = (user && q) ? (jint)strlen(user) + (jint)strlen(q) : 0;
  if (user) {
    (*env)->ReleaseStringUTFChars(env, userId, user);
  }
  if (q) {
    (*env)->ReleaseStringUTFChars(env, query, q);
  }
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_example_jni_JNI_1Phase1_1ComplexDemo_nativeDigest(
    JNIEnv *env, jobject obj, jbyteArray data, jint mode) {
  jbyteArray out = (*env)->NewByteArray(env, 4);
  (void)mode;
  if (!out) {
    return 0;
  }
  return out;
}

JNIEXPORT void JNICALL Java_com_example_jni_JNI_1Phase1_1ComplexDemo_nativeSetField(
    JNIEnv *env, jclass cls, jobject target, jstring value) {
  jclass targetClass = (*env)->GetObjectClass(env, target);
  jfieldID field = (*env)->GetFieldID(env, targetClass, "value", "Ljava/lang/String;");
  if (field) {
    (*env)->SetObjectField(env, target, field, value);
  }
  (void)cls;
}

JNIEXPORT jstring JNICALL Java_com_example_jni_JNI_1Phase1_1ComplexDemo_nativeTransform(
    JNIEnv *env, jobject obj, jstring data, jstring path) {
  const char *cdata = (*env)->GetStringUTFChars(env, data, 0);
  const char *cpath = (*env)->GetStringUTFChars(env, path, 0);
  if (cdata) {
    (*env)->ReleaseStringUTFChars(env, data, cdata);
  }
  if (cpath) {
    (*env)->ReleaseStringUTFChars(env, path, cpath);
  }
  (void)obj;
  return data;
}
