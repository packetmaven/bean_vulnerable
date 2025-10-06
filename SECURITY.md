# Security Policy

## 🔒 Reporting a Vulnerability

The Bean Vulnerable GNN Framework is a security research tool designed to detect vulnerabilities in Java code. We take the security of our framework itself seriously.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities to:

- **Email:** packetmaven@hushmail.com
- **Subject Line:** `[SECURITY] Bean Vulnerable - [Brief Description]`

Please include the following information:

1. **Type of vulnerability** (e.g., code execution, information disclosure, denial of service)
2. **Affected component** (e.g., Joern integration, GNN model, taint tracker)
3. **Steps to reproduce** the vulnerability
4. **Potential impact** of the vulnerability
5. **Suggested fix** (if available)

### Response Timeline

- **Initial Response:** Within 48 hours
- **Acknowledgment:** Within 5 business days
- **Fix Timeline:** Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Within 90 days

### Disclosure Policy

We follow **coordinated vulnerability disclosure** principles:

1. Reporter notifies us privately
2. We investigate and develop a fix
3. We release a patch
4. We publicly disclose the vulnerability (with credit to reporter if desired)

**Embargo Period:** We request a 90-day embargo before public disclosure to allow users time to update.

## 🛡️ Supported Versions

We currently support the following versions with security updates:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 2.0.x   | ✅ Yes             | Current stable release |
| 1.x.x   | ⚠️ Limited support | Critical fixes only |
| < 1.0   | ❌ No              | Please upgrade |

## 🔐 Security Features

Bean Vulnerable includes the following security considerations:

### Input Validation
- All file paths are validated and sanitized
- User input is checked for path traversal attempts
- File size limits enforced to prevent resource exhaustion

### Dependency Security
- Regular dependency updates via Dependabot
- Known vulnerabilities tracked in GitHub Security Advisories
- Joern integration sandboxed for analysis isolation

### Code Execution Safety
- No `eval()` or dynamic code execution from user input
- Subprocess calls use parameterized arguments
- Temporary files use secure random names and proper cleanup

### Data Privacy
- No telemetry or data collection
- Analysis results remain local
- No network requests to external services (except Joern updates)

## 🚨 Known Security Considerations

As a vulnerability detection tool, Bean Vulnerable:

1. **Analyzes potentially malicious code** - Run in isolated environments when analyzing untrusted code
2. **Requires Joern installation** - Ensure Joern is obtained from official sources
3. **Generates detailed reports** - Reports may contain sensitive code snippets; handle appropriately
4. **Uses ML models** - Adversarial inputs may affect detection accuracy

### Recommended Usage Environment

For analyzing untrusted or malicious code:

- ✅ Use Docker containers or VMs
- ✅ Implement network isolation
- ✅ Restrict file system access
- ✅ Monitor resource usage
- ❌ Do not run with elevated privileges
- ❌ Do not run on production systems

## 📋 Security Checklist for Contributors

Before submitting code:

- [ ] No hardcoded credentials or API keys
- [ ] Input validation for all user-provided data
- [ ] Proper error handling (no stack traces to users)
- [ ] Dependencies are up-to-date and vulnerability-free
- [ ] No use of `eval()`, `exec()`, or dynamic code execution
- [ ] Subprocess calls use argument lists (not shell strings)
- [ ] Temporary files are created securely and cleaned up
- [ ] Security tests included for new features

## 🏆 Recognition

We believe in recognizing security researchers who help improve Bean Vulnerable:

- **Public Acknowledgment** in release notes (if desired)
- **CVE Assignment** for qualifying vulnerabilities
- **Hall of Fame** section in README (with permission)

### Security Researchers

We thank the following researchers for responsibly disclosing security issues:

*No vulnerabilities reported yet*

## 📚 Security Resources

- [OWASP Top 10 2024](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

## 🔗 Related Security Tools

Bean Vulnerable complements but does not replace:

- **SonarQube** - Static application security testing (SAST)
- **CodeQL** - Semantic code analysis
- **Semgrep** - Pattern-based scanning
- **Snyk** - Dependency vulnerability scanning
- **Binarly** - Binary and firmware vulnerability analysis with AI-powered threat detection
- **3Flatline** - Runtime application security testing (RAST) and behavioral analysis

---

**Last Updated:** October 6, 2025  
**Policy Version:** 1.0

