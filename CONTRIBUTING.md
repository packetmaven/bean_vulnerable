# Contributing to Bean Vulnerable GNN Framework

Thank you for your interest in contributing to Bean Vulnerable! This document provides guidelines for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Research Contributions](#research-contributions)

## 🤝 Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and professional environment. We are committed to providing a harassment-free experience for everyone.

### Our Standards

**Positive behaviors:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behaviors:**
- Harassment, trolling, or discriminatory comments
- Personal attacks or insults
- Publishing others' private information
- Any conduct inappropriate in a professional setting

## 🚀 Getting Started

### Prerequisites

- Python 3.11 (critical for DGL compatibility)
- Git for version control
- Joern for CPG generation ([installation guide](https://docs.joern.io/installation))
- Graphviz for graph visualization

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/bean_vulnerable.git
cd bean_vulnerable
```

3. Add upstream remote:

```bash
git remote add upstream https://github.com/packetmaven/bean_vulnerable.git
```

## 💻 Development Setup

### 1. Create Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Development Dependencies

```bash
# Core dependencies
pip install --upgrade pip setuptools wheel
pip install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cpu
pip install dgl==2.1.0 -f https://data.dgl.ai/wheels/torch-2.1/repo.html

# Install framework in editable mode
pip install -e .

# Development tools (optional but recommended)
pip install pytest pytest-cov black pylint mypy
```

### 3. Verify Installation

```bash
python verify_installation.py
bean-vuln tests/samples/VUL001_SQLInjection_Basic.java --summary
```

## 🔧 How to Contribute

### Types of Contributions

We welcome:

1. **Bug Fixes** - Fix issues reported in GitHub Issues
2. **New Features** - Implement new vulnerability detection patterns
3. **Documentation** - Improve docs, add examples, write tutorials
4. **Test Cases** - Add test files for new vulnerability types
5. **Performance Improvements** - Optimize analysis speed or accuracy
6. **Research Integration** - Integrate new academic techniques

### Finding Issues

- Check [GitHub Issues](https://github.com/packetmaven/bean_vulnerable/issues)
- Look for `good first issue` or `help wanted` labels
- Ask in discussions if you're unsure where to start

### Proposing Changes

For **major changes** (new features, breaking changes):
1. Open an issue first to discuss
2. Wait for maintainer feedback
3. Implement after approval

For **minor changes** (bug fixes, docs):
1. Create a branch and implement
2. Submit a pull request directly

## 📝 Coding Standards

### Python Style Guide

We follow **PEP 8** with these specifics:

```python
# Naming Conventions
class MyClass:  # PascalCase for classes
    pass

def my_function():  # snake_case for functions
    pass

MY_CONSTANT = 42  # UPPER_CASE for constants

# Line Length
# Maximum 100 characters (soft limit)
# Maximum 120 characters (hard limit)

# Imports
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Blank Lines
# 2 blank lines before class definitions
# 1 blank line between methods
```

### Code Formatting

We use **Black** for automatic formatting:

```bash
black src/ tests/
```

### Type Hints

Use type hints for function signatures:

```python
def analyze_code(source_code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze Java source code for vulnerabilities.
    
    Args:
        source_code: Java source code as string
        file_path: Optional path to source file
        
    Returns:
        Dictionary containing analysis results
    """
    pass
```

### Documentation

Use **Google-style docstrings**:

```python
def detect_sql_injection(code: str) -> List[Dict[str, Any]]:
    """
    Detect SQL injection vulnerabilities in Java code.
    
    This function uses pattern matching and taint analysis to identify
    potential SQL injection points where user input flows into SQL queries.
    
    Args:
        code: Java source code to analyze
        
    Returns:
        List of detected vulnerabilities, each containing:
            - type: Vulnerability type ("sql_injection")
            - line: Line number
            - severity: Severity score (0-100)
            - description: Human-readable description
            
    Raises:
        ValueError: If code is empty or invalid
        
    Example:
        >>> code = 'String query = "SELECT * FROM users WHERE id=" + userId;'
        >>> results = detect_sql_injection(code)
        >>> print(results[0]['type'])
        'sql_injection'
    """
    pass
```

## 🧪 Testing Guidelines

### Writing Tests

Place tests in `tests/` directory:

```
tests/
  ├── test_vulnerability_detection.py
  ├── test_taint_tracking.py
  ├── test_alias_analysis.py
  └── samples/
      ├── VUL001_SQLInjection_Basic.java
      └── VUL002_XSS_ServletResponse.java
```

### Test Structure

```python
import pytest
from src.core.integrated_gnn_framework import IntegratedGNNFramework

class TestSQLInjectionDetection:
    """Test SQL injection detection capabilities."""
    
    @pytest.fixture
    def framework(self):
        """Create framework instance for testing."""
        return IntegratedGNNFramework()
    
    def test_basic_sql_injection(self, framework):
        """Test detection of basic SQL injection."""
        code = '''
        String query = "SELECT * FROM users WHERE id=" + userId;
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
        '''
        
        result = framework.analyze_code(code, 'test.java')
        
        assert result['vulnerability_detected'] is True
        assert result['vulnerability_type'] == 'sql_injection'
        assert result['confidence'] > 0.5
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_vulnerability_detection.py

# Run with coverage
pytest --cov=src --cov-report=html tests/

# Run only fast tests (skip slow integration tests)
pytest -m "not slow" tests/
```

### Adding Vulnerability Test Samples

When adding new vulnerability detection:

1. Create test Java file: `tests/samples/VUL0XX_[VulnType]_[Variant].java`
2. Include clear vulnerability example
3. Add docstring explaining the vulnerability
4. Test with: `bean-vuln tests/samples/VUL0XX_*.java --summary`

Example:

```java
/**
 * VUL025_LDAP_Injection.java
 * 
 * Demonstrates LDAP injection vulnerability where user input
 * is concatenated into LDAP search filters without validation.
 * 
 * CWE-90: Improper Neutralization of Special Elements in LDAP Queries
 */
public class VUL025_LDAP_Injection {
    public void vulnerableLDAPSearch(String username) throws NamingException {
        String filter = "(uid=" + username + ")";  // VULNERABLE
        ctx.search("ou=users,dc=example,dc=com", filter, constraints);
    }
}
```

## 📤 Submitting Changes

### Branch Naming

Use descriptive branch names:

```bash
# Features
git checkout -b feature/add-ldap-injection-detection

# Bug fixes
git checkout -b fix/taint-tracking-null-pointer

# Documentation
git checkout -b docs/improve-installation-guide
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format
<type>(<scope>): <short description>

<longer description>

# Examples
feat(detector): Add LDAP injection pattern detection

Implements CWE-90 detection using taint analysis and LDAP-specific
sink patterns. Includes tests for basic and advanced injection vectors.

fix(taint): Handle null pointer in interprocedural analysis

Fixes #123 where None values in method parameters caused crashes
during interprocedural taint propagation.

docs(readme): Update installation instructions for Mac Silicon

Clarifies Python 3.11 requirement and provides troubleshooting
for DGL installation issues on ARM-based Macs.
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

### Pull Request Process

1. **Update from upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests and linting:**
   ```bash
   pytest tests/
   black src/ tests/
   pylint src/
   ```

3. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create Pull Request:**
   - Go to GitHub and click "New Pull Request"
   - Fill out the PR template completely
   - Link related issues with `Fixes #123` or `Related to #456`
   - Request review from maintainers

5. **PR Checklist:**
   - [ ] Tests pass locally
   - [ ] Code follows style guidelines
   - [ ] Documentation updated (if needed)
   - [ ] CHANGELOG.md updated (for user-facing changes)
   - [ ] No merge conflicts with main branch
   - [ ] All conversations resolved

### Review Process

- Maintainers will review within 5 business days
- Address feedback by pushing new commits
- Once approved, maintainers will merge
- Squash commits if requested

## 🔬 Research Contributions

### Academic Integration

If you're integrating research from academic papers:

1. **Add citation to README:**
   ```markdown
   ### New Technique: Object-Sensitive Pointer Analysis
   
   Based on: *"Precision-Guided Context Sensitivity for Pointer Analysis"*
   Yannis Smaragdakis et al., PLDI 2015
   ```

2. **Update research foundations section**

3. **Include arXiv/DOI links**

4. **Add to `CITATIONS.bib` (if exists)**

### Benchmark Contributions

When adding new benchmarks or datasets:

- Document data source and license
- Provide reproducible scripts
- Include baseline comparisons
- Add to `benchmarks/` directory

## 🐛 Bug Reports

### Before Reporting

1. Check existing issues
2. Try latest version
3. Verify it's not a configuration issue

### Information to Include

- Bean Vulnerable version
- Python version
- Operating system
- Full command used
- Expected vs. actual behavior
- Minimal reproducible example
- Error messages/stack traces

## 💡 Feature Requests

### Format

**Problem:** Describe the problem you're trying to solve

**Proposed Solution:** Your suggested approach

**Alternatives:** Other solutions you've considered

**Use Case:** Real-world scenario where this helps

**Research:** Relevant academic papers or techniques (if applicable)

## 📧 Contact

- **Issues:** GitHub Issues
- **Security:** Open a security pull request (see `SECURITY.md`)
- **General Questions:** GitHub Discussions (when enabled)

## 🙏 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Acknowledged in academic papers (if applicable)

---

Thank you for contributing to Bean Vulnerable! Your efforts help improve software security research and practice. 🚀

