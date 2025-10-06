# Example Output Images

This directory contains example screenshots demonstrating Bean Vulnerable's analysis capabilities.

## Required Images

Please add the following images to this directory:

### 1. `cfg_example_runtime.png`
**Source:** Control Flow Graph showing runtime execution flow
- Should show: Statement-level CFG with tainted data flowing through string concatenation
- Example from: `VUL_RuntimeExecution.java` or similar

### 2. `dfg_example_file_access.png`
**Source:** Data Flow Graph illustrating path traversal
- Should show: User input flowing into file operations (new FileInputStream)
- Example from: `VUL005_PathTraversal_FileRead.java`

### 3. `alias_analysis_dashboard.png`
**Source:** HTML report showing Alias Analysis v3.0 results
- Should show: The metrics cards displaying:
  - Variables Tracked: 3
  - Field Accesses: 5
  - Tainted Fields: 1
  - Allocation Sites: 0
  - Tainted Variables: 6
  - Sanitized Variables: 0
  - Taint Flows: 6
- Also shows the "Tainted Fields Detected" section with `session.setattribute`

### 4. `advanced_taint_analysis.png`
**Source:** HTML report showing Advanced Taint Analysis metrics
- Should show: The purple gradient cards displaying:
  - ⚡ Implicit Flows: 6
  - 🎯 Context-Sensitive: 9
  - 🗺️ Path-Sensitive: 2/2
  - 🔗 Interprocedural: 2/3
  - 🔌 Native (JNI): 0/0

## Image Guidelines

- **Format:** PNG (preferred) or JPG
- **Resolution:** High-DPI (at least 1200px wide for dashboard screenshots)
- **Quality:** Clear, readable text and graph elements
- **Source:** Generated from actual Bean Vulnerable analysis runs

## How to Generate These Images

```bash
# Run analysis with HTML report
bean-vuln-enhanced tests/samples/VUL015_SessionFixation.java \
  --comprehensive \
  --html-report report_example \
  --summary

# Open the report
open report_example/index.html

# Take screenshots of:
# 1. Individual CFG/DFG graphs in the "Graph Gallery" section
# 2. Alias Analysis v3.0 Results section
# 3. Advanced Taint Analysis section
```

