#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// JNI -> native file I/O using tainted path (and intentional leak for demo).
static jstring nativeReadFileImpl(JNIEnv *env, jobject obj, jstring path) {
    const char *cpath = (*env)->GetStringUTFChars(env, path, NULL);
    FILE *fp = fopen(cpath, "rb");
    if (fp != NULL) {
        fclose(fp);
    }
    // Intentionally missing ReleaseStringUTFChars(env, path, cpath).
    return path;
}

// JNI -> native command execution sink.
static jint nativeExecuteImpl(JNIEnv *env, jobject obj, jstring command) {
    const char *cmd = (*env)->GetStringUTFChars(env, command, NULL);
    int rc = system(cmd);
    (*env)->ReleaseStringUTFChars(env, command, cmd);
    return rc;
}

// Native -> Java callback into Runtime.exec sink.
static jstring nativeCallbackExecImpl(JNIEnv *env, jobject obj, jstring command) {
    jclass runtimeCls = (*env)->FindClass(env, "java/lang/Runtime");
    jmethodID getRuntime = (*env)->GetStaticMethodID(
        env, runtimeCls, "getRuntime", "()Ljava/lang/Runtime;");
    jobject runtimeObj = (*env)->CallStaticObjectMethod(env, runtimeCls, getRuntime);
    jmethodID execMid = (*env)->GetMethodID(
        env, runtimeCls, "exec", "(Ljava/lang/String;)Ljava/lang/Process;");
    (*env)->CallObjectMethod(env, runtimeObj, execMid, command);
    return command;
}

// Native reflection-like lookup from attacker-controlled class/method strings.
static jstring nativeReflectInvokeImpl(JNIEnv *env, jobject obj, jstring className, jstring methodName, jstring arg) {
    const char *klass = (*env)->GetStringUTFChars(env, className, NULL);
    const char *method = (*env)->GetStringUTFChars(env, methodName, NULL);

    jclass target = (*env)->FindClass(env, klass);
    if (target != NULL) {
        jmethodID mid = (*env)->GetStaticMethodID(
            env, target, method, "(Ljava/lang/String;)Ljava/lang/String;");
        if (mid != NULL) {
            (*env)->CallStaticObjectMethod(env, target, mid, arg);
        }
    }

    (*env)->ReleaseStringUTFChars(env, className, klass);
    (*env)->ReleaseStringUTFChars(env, methodName, method);
    return arg;
}

static void *choose_native_read_target(void) {
    const char *mode = getenv("JNI_SWAP_MODE");
    // Attacker-influenced pointer table selection (rare but severe).
    if (mode != NULL && strstr(mode, "swap") != NULL) {
        return (void *)nativeExecuteImpl;
    }
    return (void *)nativeReadFileImpl;
}

static int attach_for_callback(JavaVM *vm) {
    JNIEnv *env = NULL;
    jint rc = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        (*vm)->AttachCurrentThread(vm, (void **)&env, NULL);
    }
    return rc;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass targetClass = (*env)->FindClass(env, "com/example/jni/JNI_Vuln_Spectrum");
    if (targetClass == NULL) {
        return JNI_ERR;
    }

    void *selectedRead = choose_native_read_target();
    JNINativeMethod methods[] = {
        {"nativeReadFile", "(Ljava/lang/String;)Ljava/lang/String;", selectedRead},
        {"nativeExecute", "(Ljava/lang/String;)I", (void *)nativeExecuteImpl},
        {"nativeCallbackExec", "(Ljava/lang/String;)Ljava/lang/String;", (void *)nativeCallbackExecImpl},
        {"nativeReflectInvoke", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void *)nativeReflectInvokeImpl},
    };

    if ((*env)->RegisterNatives(env, targetClass, methods, (jint)(sizeof(methods) / sizeof(methods[0]))) != JNI_OK) {
        return JNI_ERR;
    }

    attach_for_callback(vm);
    return JNI_VERSION_1_6;
}
