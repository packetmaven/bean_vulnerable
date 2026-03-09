# JNI Cross-Language Taint Tracking (Bean Vulnerable / bean-vuln2)

Status: Draft (design + integration plan)  
Scope: Extend `bean-vuln2` to support full, cross-language JNI taint tracking

## 1) Executive Summary
Bean Vulnerable currently exposes **experimental JNI tracking** in `ComprehensiveTaintTracker`, but it is limited to heuristic detection of `native` methods and simple taint transfer guesses. This document defines a **research-backed, full cross-language JNI taint tracking pipeline** integrated into `bean-vuln2`, using:

- **Cross-language pointer analysis** (JNIFER-class) to resolve Java↔C call edges and points-to.
- **Caller-sensitive native summaries** (from native code or specs) to propagate taint across boundaries.
- **JNI semantic modeling** to correctly interpret `JNIEnv` calls, field access, and callbacks.
- **Optional dynamic validation** (Galette-class) to confirm boundary flows.

The integration is designed to **fit existing stages** in `IntegratedGNNFramework.analyze_code()` and to **surface results in the HTML report and taint flow graphs** without breaking existing CLI behavior.

## 2) Current State in Repo (Observed Behavior)

### 2.1 Where JNI appears today
JNI tracking is currently heuristic and fully contained in `ComprehensiveTaintTracker`:

- `native` declarations are detected and logged.
- If a native method receives tainted parameters, it records a **Java→Native** transfer.
- If a native method return is assigned, it records a **Native→Java** transfer.

This is limited to **Java source only** and does not parse native code or resolve JNI calls.

Key locations:
- `src/core/comprehensive_taint_tracking.py`  
  - `_track_native_code()` detects `native` methods and simple transfers.  
  - `native_code_analysis` is included in `get_results()`.
- `src/core/integrated_gnn_framework.py`  
  - `analyze_code()` runs taint tracking in Step 1.5.
- `src/core/bean_vuln_cli_enhanced.py`  
  - `--native-jni` flag is wired to `enable_native_jni`.
- `src/core/html_report_generator.py`  
  - Displays JNI transfer metrics.

### 2.2 Limitations
- No analysis of **C/C++** native code.
- No **RegisterNatives** resolution.
- No modeling of **JNIEnv** APIs or callbacks.
- No cross-language **points-to** or **call graph**.
- No taint propagation across **native data structures**.

## 3) Research Basis (Last 9 Months)

1) **JNIFER (ICSE 2025)**  
Interactive cross-language pointer analysis for Java + C.  
Key outcome: high recall and precision for JNI interactions; integrates Tai-e (Java) and SVF (C).  
PDF: https://penguinfirst.github.io/publications/icse2025.pdf

2) **JaNA (JSSST 2025)**  
Lightweight JNI bug detection by extracting **essential cross-language context** without full global analysis.  
PDF: https://jssst.or.jp/files/user/taikai/2025/papers/5b-1-R.pdf

3) **Galette (FSE 2025)**  
Accurate dynamic taint tracking for modern JVMs, suitable as a validation oracle for JNI flow claims.  
Abstract: https://conf.researchr.org/details/fse-2025/fse-2025-research-papers/13/Dynamic-Taint-Tracking-for-Modern-Java-Virtual-Machines

## 4) Goals and Non-Goals

### Goals
- Track **taint across JNI boundaries** (Java→C and C→Java).
- Resolve **native method bindings** and **JNI callbacks**.
- Produce **explainable, boundary-aware taint graphs**.
- Integrate into `bean-vuln2` pipeline and reporting.
- Keep runtime **scalable** with clear fallbacks.

### Non-Goals
- Full formal verification of native code semantics.
- Perfect resolution for stripped/obfuscated binaries.
- Whole-system taint across OS or external native libraries.

## 5) Architecture Overview

The design introduces a **JNI cross-language analysis module** that feeds taint summaries into the existing taint engine.

```
Java Source
  └─> JNI Surface Discovery (native declarations, RegisterNatives)
       └─> Native Code Resolver (C/C++ parse, symbols)
            └─> Cross-Language Points-To (Tai-e + SVF)
                 └─> JNI Semantics + Taint Summaries
                      └─> ComprehensiveTaintTracker integration
```

## 6) Integration into Current Pipeline (bean-vuln2)

### 6.1 Existing Pipeline (reference)
From `IntegratedGNNFramework.analyze_code()`:
1. **CPG generation (Joern)**  
2. **Taint tracking** (ComprehensiveTaintTracker)  
3. **Pattern detection**  
4. **Heuristic scoring / GNN inference**  
5. **Report generation**

### 6.2 Proposed Insertion Points
- **Step 1.5**: replace the current `_track_native_code()` heuristic with a modular JNI engine that can:
  - Populate `native_code_analysis`
  - Emit cross-language edges into `taint_flow_edges`
  - Attach boundary metadata to `taint_node_metadata`

### 6.3 Updated Data Flow
1. `IntegratedGNNFramework.analyze_code()`
2. `ComprehensiveTaintTracker.analyze_java_code()`
3. `JNITaintEngine.analyze(...)` (new)
4. `ComprehensiveTaintTracker.get_results()` now includes:
   - `native_code_analysis` (expanded)
   - `taint_flow_edges` with JNI edges

## 7) New Components (Detailed)

### 7.1 `src/core/jni/jni_surface.py`
Responsibilities:
- Parse Java source for `native` declarations.
- Extract library loading (`System.loadLibrary`, `System.load`).
- Detect `RegisterNatives` patterns (if Java-side declarations exist).

Key outputs:
- `jni_methods`: [{class, name, signature, line}]
- `jni_libraries`: ["libfoo.so", ...]

### 7.2 `src/core/jni/native_resolver.py`
Responsibilities:
- Resolve Java `native` methods to **native symbols**.
- Handle:
  - **Name mangling** (`Java_pkg_Class_method`)
  - **RegisterNatives** mapping
  - **JNI_OnLoad** patterns

Key outputs:
- `resolved_bindings`: [{java_sig, native_func, confidence}]
- `unresolved_bindings`: [{java_sig, reason}]

### 7.3 `src/core/jni/jni_semantics.py`
Responsibilities:
- Model JNI APIs with semantic effects:
  - `Get*Field`, `Set*Field` -> field read/write
  - `Call*Method` -> method invocation (C→Java)
  - `GetStringUTFChars`, `GetByteArrayElements` -> native taint sources
  - `Release*` -> taint declassification (optional)

Key outputs:
- `jni_api_rules`: map of API → taint transfer rules

### 7.4 `src/core/jni/native_ir.py`
Responsibilities:
- Build native IR for C/C++ (Clang/LLVM).
- Provide normalized function bodies for analysis.

Dependencies:
- `clang`, `llvm`, optional `compile_commands.json`.

### 7.5 `src/core/jni/cross_language_points_to.py`
Responsibilities:
- Integrate Java pointer analysis (Tai-e) + C pointer analysis (SVF).
- Produce:
  - Cross-language call graph edges
  - Points-to relations for JNI handles

Key outputs:
- `jni_call_graph`
- `jni_points_to`

### 7.6 `src/core/jni/native_taint_summaries.py`
Responsibilities:
- Construct **caller-sensitive summaries** per native method:
  - Argument → return
  - Argument → field write
  - Argument → callback (C→Java)

Key outputs:
- `native_method_summaries`

### 7.7 `src/core/jni/jni_taint_engine.py`
Responsibilities:
- Orchestrate the modules above.
- Feed `ComprehensiveTaintTracker` with:
  - `native_code_analysis`
  - boundary edges and node metadata
  - taint transfer evidence

## 8) Data Model Extensions

### 8.1 `native_code_analysis` (expanded)
```json
{
  "enabled": true,
  "analysis_mode": "heuristic|summary|crosslang",
  "jni_methods": 12,
  "taint_transfers": 6,
  "resolved_bindings": [...],
  "unresolved_bindings": [...],
  "jni_call_graph": [...],
  "jni_points_to": {...},
  "jni_method_details": [...],
  "transfer_details": [...],
  "errors": [...]
}
```

### 8.2 Taint Edges (new fields)
```json
{
  "source": "param_x",
  "target": "native:Java_pkg_Class_method",
  "kind": "jni",
  "direction": "java_to_native",
  "jni_api": "CallObjectMethod",
  "language": "java|c",
  "reason": "jni_boundary"
}
```

## 9) CLI Integration (bean-vuln2)

### 9.1 New Flags
```
--jni-mode {heuristic,summary,crosslang}
--jni-native-root <path>
--jni-compile-commands <path>
--jni-binary <path>
--jni-resolve-register-natives
--jni-disable-callbacks
--jni-dynamic-validate
```

### 9.2 Behavior
- Default: `--jni-mode heuristic` (current behavior).
- `summary`: resolve bindings + apply JNI summaries without full points-to.
- `crosslang`: full JNIFER-class integration (Tai-e + SVF).

### 9.3 Where to wire
`bean_vuln_cli_enhanced.py`:
- extend `argparse` with the flags above.
- pass to `IntegratedGNNFramework`.

`IntegratedGNNFramework.__init__`:
- add `jni_mode`, `jni_native_root`, `jni_compile_commands`, etc.
- initialize `JNITaintEngine`.

`ComprehensiveTaintTracker`:
- delegate `_track_native_code()` to `JNITaintEngine` when enabled.

## 10) Reporting / UI Updates

### HTML Report
Add a **Native JNI** subsection showing:
- bound methods resolved
- callbacks discovered
- taint transfers by direction
- confidence level (heuristic vs crosslang)

### Taint Graph
Add visual markers:
- Edge color for JNI boundary
- Node badges for Java/C sides
- Tooltips showing JNI API and binding evidence

## 11) Testing Strategy

### Unit Tests
- JNI surface parser (native method extraction).
- RegisterNatives resolution.
- JNI semantics mapping correctness.

### Integration Tests
- Small Java+JNI sample with known taint flow.
- Ensure taint passes:
  - Java source → native arg → native sink
  - Java source → native → Java callback → sink

### End-to-End Tests
- `bean-vuln2 --jni-mode crosslang` produces non-zero JNI metrics.
- HTML report shows JNI transfers with correct counts.

## 12) Rollout Plan

1. **Phase 1 (Heuristic+)**  
   - Add JNI surface discovery + binding resolution.
   - Add JNI API semantics (summary-only).

2. **Phase 2 (Cross-language points-to)**  
   - Integrate Tai-e + SVF for cross-language edges.
   - Generate caller-sensitive summaries.

3. **Phase 3 (Validation)**  
   - Optional dynamic taint validation.
   - Compare static vs dynamic results.

## 13) Risks and Mitigations
- **Missing native source** → fallback to binding + summary only.
- **Large native code** → analyze only JNI-reachable functions.
- **Performance** → add caching + incremental analysis.
- **JNI API coverage** → prioritize high-risk APIs first.

## 14) Definition of Done
- Cross-language JNI taint paths appear in report and graphs.
- At least one test case validates Java↔C taint propagation.
- `bean-vuln2` exposes `--jni-mode` controls and logs resolution quality.

