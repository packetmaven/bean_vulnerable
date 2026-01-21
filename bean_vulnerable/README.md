# Bean Vulnerable GNN Framework

![Bean Vulnerable ASCII Banner](ascii-art-text.png)

A Graph Neural Network framework for vulnerability detection, exploitability assessment, and patch prioritization in Java code using ML techniques.

> **Status:** Spatial GNN inference runs by default when dependencies are present; GNN scores influence confidence only when a trained checkpoint is provided via `--gnn-checkpoint` (or disable with `--no-spatial-gnn`). Hybrid dynamic testing and RL path prioritization are **not integrated** yet. For the most accurate description of current capabilities, see the root `README.md`.

## 🎯 Overview

The Bean Vulnerable framework combines the following cutting-edge technologies:
- **Joern** for Code Property Graph (CPG) generation
- **Graph Neural Networks** with advanced loss functions
- **Pattern-based detection (current release)** with heuristic scoring; trained GNN inference is planned
- **CESCL (Cluster-Enhanced Sup-Con Loss)** for improved 0-day discovery
- **Dataset-Map + Active Learning** for intelligent data quality management
- **AEG Lite** for exploitability assessment and patch ranking
- **Counterfactual Explainers** for minimal-change security fix recommendations
- **Bayesian Uncertainty** for confidence-aware predictions
- **CVSS-like Scoring** for standardized risk assessment
- **CI Quality Guard** for production deployment safety

## ⚠️ **Prototype Setup Notes (Mac Silicon)**

### 🚀 **Quick Start**

```bash
# 1. Use Python 3.11 (critical for DGL compatibility)
python3.11 -m venv venv_bean_311
source venv_bean_311/bin/activate

# 2. Install dependencies (CPU wheels shown)
pip install --upgrade pip setuptools wheel
pip install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cpu
pip install torchdata==0.7.0
pip install dgl==2.1.0 -f https://data.dgl.ai/wheels/torch-2.1/repo.html
pip install -r requirements.txt
pip install transformers==4.37.2
pip install -e .

# 3. Verify installation
python verify_installation.py

# 4. Test with sample file
bean-vuln tests/samples/VUL001_SQLInjection_Basic.java --summary
```

## 🔧 Advanced Mac Silicon Setup & Usage (Latest)

The following section mirrors the latest, fully validated commands from `README_beanv.md` and adds advanced runtime options for robustness, proof artifacts, and calibrated confidence.

### Use the project virtualenv (Python 3.11)
```bash
source '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/activate'
```

Optional `.venv` symlink (helps IDEs):
```bash
ln -s '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env' '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/.venv'
```

### Exact dependency install (inside venv)
```bash
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip install --upgrade pip setuptools wheel
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip install --no-cache-dir torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cpu
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip install --no-cache-dir torchdata==0.7.0
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip install --no-cache-dir dgl==2.1.0 -f https://data.dgl.ai/wheels/torch-2.1/repo.html
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip install 'numpy<2'
```

Torch-Geometric (CPU wheels matching torch 2.1.0):
```bash
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip install --no-cache-dir \
  pyg-lib==0.3.1+pt21 torch-scatter==2.1.2 torch-sparse==0.6.18 \
  torch-cluster==1.6.3 torch-spline-conv==1.2.2 torch-geometric==2.6.1 \
  -f https://data.pyg.org/whl/torch-2.1.0+cpu.html
```

CodeBERT embeddings require transformers (torch 2.1 compatible):
```bash
pip install transformers==4.37.2
```

### Quick verification
```bash
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -c 'import torch, torchdata, dgl; print("OK", torch.__version__, torchdata.__version__, dgl.__version__)'
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -c 'import torch; print("MPS", torch.backends.mps.is_available())'
```

### Prevent conda from interfering (optional)
If your shell shows “(base)” or conda auto-activates, disable it and/or uninstall the Homebrew miniconda cask:
```bash
/usr/bin/sed -i '' -e '/conda.sh/d' -e '/conda shell.zsh hook/d' -e '/miniconda3/d' -e '/anaconda3/d' '/Users/<your-username>/.zshrc'
/opt/homebrew/bin/brew uninstall --cask miniconda || true
/bin/rm -rf '/opt/homebrew/Caskroom/miniconda' || true
```
Reload shell:
```bash
/bin/zsh -lc 'source /Users/<your-username>/.zshrc'
```

### Advanced runtime options (robustness, proof, calibration)

> **Note:** The flags shown below are **not implemented** in the current CLI. Use `bean-vuln --help` to see supported options.

- Single-file run with supported flags:
```bash
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/bean-vuln --summary --out '/tmp/bean_one.json' '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/tests/samples/VUL003_CommandInjection_Runtime.java'
```

- Inspect calibrated confidence, robust consensus, DFG metric, and graph sanity in JSON:
```bash
/usr/bin/grep -n '"calibrated_confidence"' '/tmp/bean_one.json'
/usr/bin/grep -n '"robust"' '/tmp/bean_one.json'
/usr/bin/grep -n '"dfg"' '/tmp/bean_one.json'
/usr/bin/grep -n '"graph_sanity"' '/tmp/bean_one.json'
```

- Proof bundle artifacts (created by `--proof --evidence-output`):
```bash
/bin/ls -l '/tmp/bean_proof'
/bin/cat '/tmp/bean_proof/evidence_spans.json'
/bin/cat '/tmp/bean_proof/cpg_slice.json'
```

### Apple Silicon optimizations (optional)
Environment tweaks are not shipped in this repo. Use standard Python/MPS settings and consult PyTorch docs if needed.

- Directory summary (aggregates per-file; `heuristic:True` if any file triggered pattern detection):
```bash
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/bean-vuln --summary '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/tests/samples'
```

### Console script vs module invocation
If the console script hasn’t refreshed, either reinstall with PEP 517 or call the module directly:
```bash
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip uninstall -y bean-vulnerable-gnn
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python -m pip install -e '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo' --use-pep517
hash -r
```
Module form:
```bash
/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/fresh_bean_test_env/bin/python '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/src/core/bean_vuln_cli.py' --summary --out '/tmp/bean_one.json' '/Users/<your-username>/src/github.com/your-org/bean_vulnerable_gnn_repo/tests/samples/VUL003_CommandInjection_Runtime.java'
```

### Notes & Tips

- “mps:0” is the Apple GPU device index (analogous to “cuda:0” on NVIDIA).
- Torch-Geometric warnings on ARM CPU wheels are OK; the install above is CPU-only and tested.
- ✅ AEG lite extension loaded successfully
- 🔍 Analyzing: tests/samples/VUL001_SQLInjection_Basic.java
- 📊 Vulnerability detected: True (Confidence: 69.3%)
- ⚡ AEG Analysis: Exploitability Score: 0.400, Confidence: 0.500
```

## 🔧 **Command Reference (Supported)**

### **Basic File Analysis**
```bash
# Scan a single Java file
bean-vuln path/to/file.java

# Scan with summary output  
bean-vuln path/to/file.java --summary

# Scan multiple specific files
bean-vuln file1.java file2.java file3.java
```

### **Directory Scanning**
```bash
# Scan all Java files in a directory
bean-vuln path/to/directory

# Recursive directory scan
bean-vuln path/to/directory --recursive

# Alternative syntax for directory scanning
bean-vuln path/to/directory/ --recursive
```

### **Advanced Features (Experimental / Partial)**
> Some advanced flags enable experimental or stubbed functionality; check `bean-vuln --help` for current support.
```bash
# Scan with ensemble methods (improved accuracy)
bean-vuln file.java --ensemble

# Experimental feature engineering (not used in scoring)
bean-vuln file.java --advanced-features

# Scan with counterfactual explanations (AST-aware)
bean-vuln file.java --explain

# Comprehensive scan (all features)
bean-vuln file.java --comprehensive
```

### **AEG Lite (Prototype)**
AEG Lite is a prototype binary-analysis module and is **not exposed in the CLI** yet.

### **Output and Reporting**
```bash
# Save results to JSON file
bean-vuln file.java --out report.json

# Enable verbose logging
bean-vuln file.java --verbose
```

### **Example Runs**
```bash
# Single file scan (SQL Injection - 69.3% confidence)
bean-vuln tests/samples/VUL001_SQLInjection_Basic.java --summary

# Command Injection detection (Working)
bean-vuln tests/samples/VUL003_CommandInjection_Runtime.java --summary

# XSS detection (Working)
bean-vuln tests/samples/VUL006_XSS_ServletResponse.java --summary

# Batch processing (24 files in ~90 seconds)
bean-vuln tests/samples/ --recursive --summary

# Advanced features with counterfactual explanations
bean-vuln tests/samples/VUL001_SQLInjection_Basic.java --ensemble --advanced-features --explain --summary
```

## 📊 **Verified Performance Results**

### **Vulnerability Detection Success**
- **Files Processed**: 24 sample files
- **Vulnerabilities Detected**: 14 confirmed
- **Vulnerability Types**: SQL Injection, Command Injection, XSS, Buffer Overflow, Hardcoded Credentials, etc.
- **Processing Speed**: ~90 seconds for 24 files
- **Framework Initialization**: ✅ Success ("AEG lite extension loaded successfully")

### **Advanced Features Tested**
- ✅ **Ensemble Methods**: Voting, BMA, stacking classifiers
- ⚠️ **Feature Engineering**: Experimental stubs (not used in scoring)
- ✅ **AEG Lite**: Binary analysis, exploitability scoring, patch ranking
- ✅ **Counterfactual Explanations**: AST-aware minimal-change recommendations
- ✅ **Bayesian Uncertainty**: Confidence-aware predictions
- ✅ **Mac Silicon Optimizations**: MPS GPU acceleration, ARM64 native binaries

### **Sample Detection Results**
```
VUL001_SQLInjection_Basic.java: ✅ Detected (69.3% confidence)
VUL003_CommandInjection_Runtime.java: ✅ Detected 
VUL006_XSS_ServletResponse.java: ✅ Detected
VUL011_WeakCrypto_DES.java: ✅ Detected
VUL012_HardcodedCredentials.java: ✅ Detected
VUL013_BufferOverflow_Array.java: ✅ Detected
... (14 total vulnerabilities detected)
```

## 🚨 DGL Dependency Issues**

### "No module named 'angr'" Error

The original error was caused by:
1. Missing `angr` dependency for AEG Lite features
2. DGL compatibility issues with newer Python versions
3. Complex dependency chain problems (PyTorch + torchdata + DGL)

### **Solution**: Manual Version Pinning
Use the exact versions below to avoid DGL/PyTorch compatibility issues:
- ✅ **Python 3.11 compatibility** (DGL has full support)
- ✅ **Exact version matching** (PyTorch 2.1.0 + torchdata 0.7.0 + DGL 2.1.0)
- ✅ **angr installation** (9.2.166 works perfectly on Apple Silicon)
- ✅ **All dependencies** (NetworkX, GitPython, diff-match-patch, etc.)
- ✅ **Mac Silicon optimizations** (MPS GPU acceleration)

### **Critical Version Requirements** (Tested Working)
```bash
Python: 3.11.13
PyTorch: 2.1.0 (with MPS support)
DGL: 2.1.0 (with GraphBolt)
torchdata: 0.7.0 (exact version required)
angr: 9.2.166 (AEG Lite support)
NetworkX: 3.2.1
NumPy: 1.26.4 (constrained to <2)
```

## 📦 Framework Installation

### Mac Silicon Installation (Recommended)
```bash
# 1. Install Python 3.11 using Homebrew
brew install python@3.11

# 2. Create virtual environment
python3.11 -m venv venv_bean_311
source venv_bean_311/bin/activate

# 3. Install dependencies (CPU wheels shown)
pip install --upgrade pip
pip install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cpu
pip install torchdata==0.7.0
pip install dgl==2.1.0 -f https://data.dgl.ai/wheels/torch-2.1/repo.html
pip install -r requirements.txt
pip install -e .

# 4. Verify installation
python verify_installation.py
```

### Alternative Manual Installation
```bash
# Create virtual environment
python3.11 -m venv venv_bean_311
source venv_bean_311/bin/activate

# Install exact working versions
pip install --upgrade pip
pip install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cpu
pip install torchdata==0.7.0
pip install dgl==2.1.0 -f https://data.dgl.ai/wheels/torch-2.1/repo.html
pip install "numpy<2" pydantic pyyaml pandas
pip install angr>=9.2.0 GitPython>=3.1.0 diff-match-patch>=20230430

# Install remaining requirements
pip install -r requirements.txt

# Install Bean Vulnerable package (enables bean-vuln command)
pip install -e .
```

## 🔍 Understanding the Output

### Basic Analysis Output
```json
{
  "vulnerability_detected": true,
  "vulnerability_types": ["sql_injection", "command_injection", "xss"],
  "confidence_scores": {
    "traditional": 1.0000,
    "bayesian": 0.9004,
    "cescl": 0.4005,
    "final_weighted": 0.7204
  },
  "uncertainty_level": "medium",
  "cpg_metrics": {
    "nodes": 133,
    "edges": 27,
    "methods": 8,
    "calls": 12,
    "identifiers": 15
  },
  "analysis_time_seconds": 5.2
}
```

### Enhanced Analysis with AEG Lite
```json
{
  "vulnerability_detected": true,
  "vulnerability_types": ["command_injection"],
  "confidence_scores": {
    "final_weighted": 0.7204
  },
  "aeg_analysis": {
    "exploitability_score": 6.6,
    "cvss_like_score": 6.6,
    "risk_level": "medium",
    "feasibility": "moderate",
    "attack_complexity": "low",
    "impact_assessment": {
      "confidentiality": "high",
      "integrity": "high",
      "availability": "medium"
    }
  },
  "combined_risk": 4.76
}
```

## 🎯 Interpreting Confidence Scores

### Final Weighted Confidence (Recommended)
Heuristic confidence combines Bayesian and traditional approaches:
- **Heuristic formula**: `0.7 * Bayesian + 0.3 * Traditional`

When spatial GNN inference runs **and** trained weights are loaded:
- **GNN blend**: `0.5 * Heuristic + 0.5 * GNN`
- **0.8+**: High confidence, proceed with remediation
- **0.6-0.8**: Good confidence, validate findings  
- **0.4-0.6**: Moderate confidence, manual review recommended
- **< 0.4**: Low confidence, likely false positive

**Calibration status:** Heuristic only. No empirical calibration set is bundled yet; use uncertainty metrics for manual triage.

### Exploitability Scores (CVSS-like 0.0-10.0)
- **9.0-10.0**: Critical - Immediate action required
- **7.0-8.9**: High - Prioritize for next release
- **4.0-6.9**: Medium - Address in current sprint
- **0.1-3.9**: Low - Schedule for future release
- **0.0**: None - No exploitability concerns

## 🛡️ Security Practitioner Usage

### Blue Team (Defensive Security)
```bash
# Comprehensive security assessment
bean-vuln /production/source --recursive --ensemble --summary

# Generate security fix recommendations
bean-vuln vulnerable.java --explain --out fixes.json

# CI/CD security gate
bean-vuln $CHANGED_FILE --summary --out ci_report.json
```

### Red Team (Offensive Security)  
```bash
# Exploitability analysis (prototype; not exposed in CLI yet)
bean-vuln target.java --summary

# Counterfactual analysis for exploit development
bean-vuln target.java --explain --verbose

# Batch target assessment
bean-vuln /target/source --recursive --out targets.json
```

## 🧪 Testing and Validation

### Test Framework Functionality
```bash
# Test basic framework initialization
python -c "
from src.core.integrated_gnn_framework import IntegratedGNNFramework
fw = IntegratedGNNFramework()
print('✅ Framework test passed')
"

# Test with provided samples
bean-vuln tests/samples/VUL001_SQLInjection_Basic.java --summary

# Run comprehensive test suite
python -m pytest tests/ -v
```

### Expected Test Results
```
✅ Framework initialization: SUCCESS
✅ Joern integration: WORKING  
⚠️ DGL graph modules: OPTIONAL (not used in scoring)
✅ AEG Lite extension: LOADED
✅ Sample vulnerability detection: 14/24 files detected
⚠️ Advanced features: PARTIAL/EXPERIMENTAL
```

## 🏗️ Architecture Overview

```
Source Code → Joern CPG → Heuristic Scoring + Bayesian → Vulnerability Output
     ↓            ↓                 ↓                      ↓
  Java File → CPG Metrics → Pattern + Uncertainty → Risk Assessment
                                   ↓                      ↓
                          CF-Explainers → Security Fix Recommendations
```

### Core Components (Current)
1. **JoernIntegrator**: CPG generation and analysis ✅
2. **CESCLLoss**: Cluster-enhanced contrastive learning (module available) ⚠️
3. **DatasetMapAnalyzer**: Quality assessment and active learning (module available) ⚠️
4. **AEGLite**: Exploitability assessment engine (prototype; binary analysis) ⚠️
5. **Enhanced CF-Explainer**: AST-aware counterfactual generation ✅
6. **Spatial GNN (experimental)**: Optional inference; trained weights required for accuracy ⚠️
7. **IntegratedGNNFramework**: Main orchestrator ✅

The Bean Vulnerable Framework is a **prototype** on Mac Silicon with:

- ✅ **Pinned dependency guidance** for known DGL/PyTorch issues
- ⚠️ **AEG Lite** uses binary analysis and mock builds when no build script exists
- ⚠️ **Advanced features** are partially implemented or experimental stubs
- ✅ **Vulnerability detection** works on bundled samples (heuristic)
- ✅ **Counterfactual explanations** (AST-aware recommendations)

## 📞 Support

For issues or questions:
1. Check the comprehensive troubleshooting section above
2. Verify Python 3.11 is being used (required for DGL)
3. Ensure all dependencies match the exact versions specified
4. Run the verification commands to confirm setup
