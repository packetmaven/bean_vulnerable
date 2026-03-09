# JNI Binding Spectrum and Evidence Model

This note captures the JNI binding mechanisms we support and the evidence we store in analysis results.

## Sources

- Oracle JNI design overview: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/design.html
- Oracle JNI functions spec: https://docs.oracle.com/en/java/javase/21/docs/specs/jni/functions.html
- Oracle JNI invocation spec: https://docs.oracle.com/en/java/javase/21/docs/specs/jni/invocation.html

## Binding Mechanisms

### 1) Static name-mangled bindings

- Pattern: `Java_<pkg>_<class>_<method>` with JNI escaping.
- Escapes from spec:
  - `_1` for `_`
  - `_2` for `;` in signatures
  - `_3` for `[` in signatures
- Overload form includes method signature suffix with `__`.

### 2) Dynamic registration via RegisterNatives

- Native code may register Java method name/signature to arbitrary native function pointer.
- Usually appears in `JNI_OnLoad`, but can appear in other init functions.
- Evidence needed:
  - registration table entries (`name`, `signature`, `fnPtr`)
  - registration call site (`RegisterNatives` line/function)
  - class target (`FindClass` value when available)

### 3) JNI lifecycle entry points

- `JNI_OnLoad`, `JNI_OnUnload`, and statically linked variants (`JNI_OnLoad_L`).
- Relevant to identify where dynamic registration is performed.

### 4) Invocation API and native-initiated Java calls

- `JNI_CreateJavaVM`, `AttachCurrentThread`, `AttachCurrentThreadAsDaemon`, `GetEnv`.
- Signals native-initiated Java execution contexts and callback capability.

### 5) Native -> Java callbacks

- `FindClass`, `GetMethodID`/`GetStaticMethodID`, `Call*Method` family.
- Useful for detecting native-controlled callbacks into sensitive Java sinks.

## Evidence Fields (JSON)

Under `taint_tracking.native_code_analysis`:

- `analysis_mode`: `heuristic|summary|crosslang`
- `jni_methods`: count of native declarations discovered in Java.
- `jni_libraries`: Java-side loaded libs (`System.load*`).
- `resolved_bindings`: list of binding objects with confidence and source.
- `unresolved_bindings`: list of candidates with reasons.
- `dynamic_registrations`: entries parsed from `JNINativeMethod`/`RegisterNatives`.
- `invocation_api_usage`: counts for `JNI_CreateJavaVM`, `AttachCurrentThread`, `GetEnv`, etc.
- `callback_api_usage`: counts for `FindClass`, `GetMethodID`, `Call*Method`, etc.
- `jni_api_usage`: general JNI API counts (source scan).
- `taint_transfers`: Java->native and native->Java transfer evidence.
- `errors`: non-fatal resolver/parser issues.

Each resolved binding should include:

- `java_name`
- `signature` (if known)
- `mangled`
- `native_func`
- `binding_type`: `static|register_natives|invocation|symbol_only`
- `resolver`: `source_scan|register_natives|symbol_table`
- `confidence`: e.g., `high`, `medium`, `low` or implementation string
- `file`, `line`

## Security-Relevant Patterns to Surface

- Tainted path passed to JNI file APIs.
- Tainted command passed to JNI `system`/`exec` pathways.
- Native callback chain into Java sink APIs.
- Missing release calls for acquired JNI resources.
- Attacker-controlled reflection identifiers crossing JNI boundary.
- RegisterNatives tables that can be influenced at runtime.
