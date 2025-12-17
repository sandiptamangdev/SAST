# SAST - Static Analysis Security Tool
Automated code review assistant for vulnerability detection using Python, Bandit, Pylint, and security frameworks

🔗 **Repository:** https://github.com/sandiptamangdev/SAST

---

## 📅 Daily Progress Log

### [2025-12-15]
**📚 What I Learned:**
**Topic: Python File I/O – Basic Operations**

**What I Did Today:**
Practiced creating, reading, and appending to files in Python.

**Exercises**

- Create a file named example.txt and write "Hello World" to it.
- open example.txt and read its content. Print it.
- Append "Welcome to Python" to the same file.

**⏱️ Time Spent:** ~ 1 hours

**🔒 Security Findings:**
* 

### [2025-12-16]
**📚 What I Learned:**
- File input output operation.

**💻 What I Built:**
- completed from Q4 to Q8

**🐛 Challenges:**
- Reading 1 character at a time

**⏱️ Time Spent:** NaN

### [2025-12-16]
**📚 What I Learned:**
- File input output operation.

**💻 What I Built:**
- completed from Q9 to Q10

**⏱️ Time Spent:** NaN



## 📋 Project Tasks Checklist

### Phase 1: Environment Setup & Foundation ✅ COMPLETED
- [x] **Task 1:** Set up project structure (folders, README, LICENSE)
- [x] **Task 2:** Create virtual environment and install dependencies
- [x] **Task 3:** Initialize Git repository and create .gitignore
- [x] **Task 4:** Set up Ubuntu/Kali Linux VM for testing
- [x] **Task 5:** Document project overview and goals

---

### Phase 2: Tool Integration & Basic Scanning
- [ ] **Task 6:** Install and configure Bandit for security analysis
  - Install Bandit: `pip install bandit`
  - Test basic scanning: `bandit -r ./tests`
  - Understand output format (JSON, CSV, HTML)
- [ ] **Task 7:** Integrate Pylint for code quality checks
  - Install Pylint: `pip install pylint`
  - Run on sample files and parse output
  - Configure custom rules in `.pylintrc`
- [ ] **Task 8:** Integrate Flake8 for style checking
  - Install Flake8: `pip install flake8`
  - Test with security plugins: `flake8-bandit`
  - Parse output programmatically
- [ ] **Task 9:** Create wrapper functions for each tool
  - `run_bandit(filepath)` → returns JSON results
  - `run_pylint(filepath)` → returns dict of issues
  - `run_flake8(filepath)` → returns list of violations
- [ ] **Task 10:** Aggregate results from all tools into unified format
  - Create `Finding` class/dict structure
  - Merge results from Bandit, Pylint, Flake8
  - Remove duplicates

---

### Phase 3: Security Framework Mapping
- [ ] **Task 11:** Study and document OWASP Top 10 (2021)
  - Read official OWASP documentation
  - Create mapping table: vulnerability → OWASP category
  - Add OWASP references to findings
- [ ] **Task 12:** Study and implement CWE classification
  - Research common CWEs (CWE-89, CWE-79, CWE-798, etc.)
  - Create `cwe_mapping.json` file
  - Map detected issues to CWE IDs
- [ ] **Task 13:** Study MITRE ATT&CK framework
  - Understand tactics and techniques
  - Create mapping: vulnerability → MITRE technique
  - Document relevant attack patterns
- [ ] **Task 14:** Create severity scoring algorithm
  - Define severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
  - Implement scoring based on CWE, exploitability, impact
  - Test scoring on sample vulnerabilities
- [ ] **Task 15:** Enrich findings with framework metadata
  - Add OWASP, CWE, MITRE tags to each finding
  - Include severity scores
  - Add descriptions and references

---

### Phase 4: Custom Vulnerability Detection (AST-Based)
- [ ] **Task 16:** Learn Python AST (Abstract Syntax Tree) basics
  - Study `ast` module documentation
  - Practice parsing Python files
  - Understand node types (Call, Import, Assign, etc.)
- [ ] **Task 17:** Implement SQL Injection detector
  - Create `SQLInjectionDetector` class using AST visitor
  - Detect string concatenation in SQL queries
  - Flag `.execute()` calls with concatenated strings
- [ ] **Task 18:** Implement hard-coded secrets detector
  - Use regex to find API keys, passwords, tokens
  - Patterns: `api_key = "..."`, `password = "..."`
  - Check variable names and string literals
- [ ] **Task 19:** Implement command injection detector
  - Detect `os.system()`, `subprocess.call()` with `shell=True`
  - Flag user input in system commands
  - Check for proper input sanitization
- [ ] **Task 20:** Implement weak cryptography detector
  - Find imports of MD5, SHA1, DES
  - Detect hard-coded encryption keys
  - Flag insecure random number generation (`random` vs `secrets`)

---

### Phase 5: Report Generation & Output
- [ ] **Task 21:** Design JSON report schema
  - Include scan metadata (date, files scanned, duration)
  - List all findings with full details
  - Add statistics (total vulns, by severity, by type)
- [ ] **Task 22:** Implement JSON report generator
  - Create `generate_json_report()` function
  - Save to `reports/scan_YYYYMMDD_HHMMSS.json`
  - Ensure proper JSON formatting and validation
- [ ] **Task 23:** Create HTML report template (Jinja2)
  - Design clean, professional HTML layout
  - Use Bootstrap/Tailwind for styling
  - Add syntax highlighting for code snippets
- [ ] **Task 24:** Implement HTML report generator
  - Render Jinja2 template with findings data
  - Add charts/graphs for severity distribution
  - Include mitigation recommendations
- [ ] **Task 25:** Add PDF export option (optional)
  - Research PDF generation libraries (ReportLab, WeasyPrint)
  - Convert HTML report to PDF
  - Test with different report sizes

---

### Phase 6: CLI & User Experience
- [ ] **Task 26:** Create command-line interface with argparse
  - `--source` or `-s` for file/directory path
  - `--output` or `-o` for report output path
  - `--format` for report type (json, html, pdf)
  - `--severity` to filter by severity level
- [ ] **Task 27:** Add progress indicators for long scans
  - Use `tqdm` for progress bars
  - Show "Scanning file X of Y..."
  - Display elapsed time
- [ ] **Task 28:** Implement logging system
  - Use Python's `logging` module
  - Log to both console and file (`logs/sast.log`)
  - Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- [ ] **Task 29:** Add configuration file support (config.yaml)
  - Define scan rules, excluded patterns, severity thresholds
  - Load config at startup
  - Allow CLI args to override config
- [ ] **Task 30:** Create helpful error messages and hints
  - Validate file paths before scanning
  - Check if tools (Bandit, Pylint) are installed
  - Provide clear error messages with solutions

---

### Phase 7: Advanced Features & Optimization
- [ ] **Task 31:** Implement file exclusion patterns
  - Skip test files, migrations, third-party libs
  - Use glob patterns (e.g., `*.test.py`, `migrations/*`)
  - Add to config file
- [ ] **Task 32:** Add baseline/differential scanning
  - Save previous scan results
  - Compare with current scan
  - Show only new vulnerabilities
- [ ] **Task 33:** Implement false positive suppression
  - Allow marking findings as false positives
  - Store in `.sast_ignore` file
  - Skip suppressed findings in future scans
- [ ] **Task 34:** Add support for custom security rules
  - Allow users to define custom AST visitors
  - Load rules from `custom_rules/` directory
  - Document rule creation process
- [ ] **Task 35:** Optimize performance for large codebases
  - Implement parallel file scanning (multiprocessing)
  - Cache AST parsing results
  - Add timeout for slow files

---

### Phase 8: Testing & Quality Assurance
- [ ] **Task 36:** Create vulnerable test files
  - `test_sql_injection.py` with various SQL injection patterns
  - `test_secrets.py` with hard-coded credentials
  - `test_command_injection.py` with unsafe system calls
  - `test_crypto.py` with weak algorithms
- [ ] **Task 37:** Write unit tests for detectors
  - Test SQL injection detector accuracy
  - Test secrets detector with various formats
  - Test command injection detector edge cases
  - Aim for >80% code coverage
- [ ] **Task 38:** Create integration tests
  - Test full scan workflow (input → analysis → report)
  - Test with real-world vulnerable projects
  - Verify framework mapping accuracy
- [ ] **Task 39:** Test on real open-source projects
  - Scan popular Python projects from GitHub
  - Analyze false positive rate
  - Benchmark performance (files/sec)
- [ ] **Task 40:** Validate against known vulnerabilities (CVEs)
  - Find projects with known CVEs
  - Verify SAST detects them
  - Document detection rate

---

### Phase 9: Documentation & Polish
- [ ] **Task 41:** Write comprehensive README
  - Clear project description
  - Installation instructions
  - Usage examples with screenshots
  - Contributing guidelines
- [ ] **Task 42:** Create detailed usage guide
  - Step-by-step tutorial
  - Explain command-line options
  - Show example reports
  - Troubleshooting section
- [ ] **Task 43:** Document detection rules
  - List all vulnerability types detected
  - Explain detection logic for each
  - Provide code examples (vulnerable vs secure)
- [ ] **Task 44:** Add code comments and docstrings
  - Document all functions with docstrings
  - Add inline comments for complex logic
  - Follow PEP 257 conventions
- [ ] **Task 45:** Create video demo/walkthrough
  - Record tool demonstration
  - Show scanning process
  - Explain report interpretation
  - Upload to YouTube/GitHub

---

### Phase 10: Future Enhancements (Post-MVP)
- [ ] **Task 46:** Add support for JavaScript/TypeScript
  - Research JS SAST tools (ESLint, JSHint)
  - Implement JS-specific detectors
  - Extend report format
- [ ] **Task 47:** Add support for Java
  - Integrate SpotBugs or PMD
  - Detect Java-specific vulnerabilities
  - Handle large Java projects
- [ ] **Task 48:** Implement ML-based anomaly detection
  - Train model on vulnerable code patterns
  - Use for advanced threat detection
  - Research existing ML security models
- [ ] **Task 49:** Create IDE integration (VS Code extension)
  - Real-time security feedback
  - Inline vulnerability warnings
  - Quick-fix suggestions
- [ ] **Task 50:** Build web dashboard for results
  - Interactive vulnerability explorer
  - Trend analysis over time
  - Team collaboration features

---

## 🎯 Project Goals
- [x] Set up project infrastructure and environment
- [ ] Integrate industry-standard SAST tools (Bandit, Pylint, Flake8)
- [ ] Implement custom AST-based vulnerability detection
- [ ] Map findings to security frameworks (OWASP, CWE, MITRE)
- [ ] Generate professional, actionable security reports
- [ ] Create intuitive CLI for developers
- [ ] Achieve high detection accuracy with low false positives
- [ ] Document thoroughly for academic/professional use

---

## 🛠️ Tech Stack

**Core Technologies:**
- Python 3.8+ (primary language)
- AST (Abstract Syntax Tree) for code analysis

**Security Tools:**
- Bandit (security-focused linting)
- Pylint (code quality analysis)
- Flake8 (style and security checking)

**Report Generation:**
- JSON (structured data)
- Jinja2 (HTML templating)
- Matplotlib/Plotly (optional charts)
- ReportLab/WeasyPrint (PDF generation)

**CLI & UX:**
- argparse (command-line interface)
- tqdm (progress bars)
- colorama (colored terminal output)
- logging (error tracking)

**Testing:**
- pytest (unit and integration tests)
- coverage.py (code coverage)

**Hosting & Deployment:**
- GitHub (version control)
- PyPI (package distribution - future)

---

## 🔒 Vulnerability Detection Coverage

### Currently Detecting:
- [ ] SQL Injection (CWE-89)
- [ ] Command Injection (CWE-78)
- [ ] Hard-coded Secrets (CWE-798)
- [ ] Weak Cryptography (CWE-327)
- [ ] Path Traversal (CWE-22)
- [ ] Insecure Deserialization (CWE-502)
- [ ] XSS (CWE-79) - if applicable
- [ ] SSRF (CWE-918)
- [ ] XXE (CWE-611)
- [ ] Insecure Random (CWE-330)

### Planned Additions:
- [ ] LDAP Injection (CWE-90)
- [ ] XML Injection (CWE-91)
- [ ] Buffer Overflow (CWE-120)
- [ ] Race Conditions (CWE-362)
- [ ] Missing Authentication (CWE-306)

---

## 📊 Security Framework Mapping

### OWASP Top 10 (2021)
- [ ] A01:2021 – Broken Access Control
- [ ] A02:2021 – Cryptographic Failures
- [ ] A03:2021 – Injection
- [ ] A04:2021 – Insecure Design
- [ ] A05:2021 – Security Misconfiguration
- [ ] A06:2021 – Vulnerable Components
- [ ] A07:2021 – Authentication Failures
- [ ] A08:2021 – Data Integrity Failures
- [ ] A09:2021 – Logging Failures
- [ ] A10:2021 – Server-Side Request Forgery

### CWE Coverage (Priority)
- [ ] CWE-89 (SQL Injection)
- [ ] CWE-78 (OS Command Injection)
- [ ] CWE-79 (XSS)
- [ ] CWE-22 (Path Traversal)
- [ ] CWE-798 (Hard-coded Credentials)
- [ ] CWE-327 (Broken Crypto)
- [ ] CWE-502 (Deserialization)

### MITRE ATT&CK
- [ ] T1190 (Exploit Public-Facing Application)
- [ ] T1059 (Command and Scripting Interpreter)
- [ ] T1552.001 (Credentials In Files)
- [ ] T1557 (Adversary-in-the-Middle)

---

## 📝 Notes & Ideas

### Detection Improvements
* Consider adding dataflow analysis to track variable usage
* Implement taint analysis for input validation tracking
* Add confidence scores to findings (LOW, MEDIUM, HIGH)
* Create a "safe pattern" whitelist to reduce false positives

### Reporting Enhancements
* Add trend graphs showing security improvements over time
* Include "security score" for codebase (0-100)
* Generate executive summary for non-technical stakeholders
* Add comparison with industry benchmarks

### Performance Optimizations
* Implement incremental scanning (only changed files)
* Use caching for repeated scans
* Add multi-threading for large projects
* Create scan checkpoints for resume capability

### Integration Ideas
* GitHub Actions workflow for automated scanning
* Pre-commit hooks to block vulnerable code
* Slack/Discord notifications for critical findings
* CI/CD pipeline integration (Jenkins, GitLab CI)

---

## 🔗 Resources

### Security Standards
* [OWASP Top 10 (2021)](https://owasp.org/Top10/)
* [CWE Top 25](https://cwe.mitre.org/top25/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Python Security
* [Bandit Documentation](https://bandit.readthedocs.io/)
* [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security.html)
* [OWASP Python Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
* [Python AST Module](https://docs.python.org/3/library/ast.html)

### SAST Tools & Techniques
* [Semgrep](https://semgrep.dev/) - Pattern-based analysis
* [SonarQube](https://www.sonarqube.org/) - Continuous inspection
* [Snyk Code](https://snyk.io/product/snyk-code/) - Developer-first security
* [CodeQL](https://codeql.github.com/) - Semantic code analysis

### Learning Resources
* [PentesterLab](https://pentesterlab.com/) - Hands-on security exercises
* [PortSwigger Web Security Academy](https://portswigger.net/web-security)
* [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
* [Damn Vulnerable Web Application](https://github.com/digininja/DVWA)

### Academic Papers
* "Static Analysis for Security" - Livshits & Lam
* "Securing Software with SAST" - NIST Special Publication
* "A Survey of Static Analysis Tools" - IEEE

---

## 🚀 Milestones

### Milestone 1: Basic Tool Integration (Week 1-2)
- [ ] All three tools (Bandit, Pylint, Flake8) integrated
- [ ] Basic CLI working
- [ ] JSON output generated

### Milestone 2: Framework Mapping (Week 3-4)
- [ ] OWASP mapping complete
- [ ] CWE classification implemented
- [ ] MITRE ATT&CK integration done

### Milestone 3: Custom Detection (Week 5-6)
- [ ] AST-based detectors working
- [ ] Top 5 vulnerabilities detected accurately
- [ ] False positive rate <20%

### Milestone 4: Reporting (Week 7)
- [ ] HTML reports generated
- [ ] Professional formatting
- [ ] Mitigation advice included

### Milestone 5: Testing & Documentation (Week 8)
- [ ] Test suite complete
- [ ] Documentation finished
- [ ] Ready for demo/presentation

---

## 🎓 Academic/Professional Use

### For Academic Projects:
- Document methodology thoroughly
- Include literature review on SAST
- Show experimental results with metrics
- Compare with commercial tools
- Discuss limitations and future work

### For Portfolio:
- Add to GitHub with detailed README
- Create demo video
- Write blog post about implementation
- Showcase unique detection algorithms
- Highlight framework integration

### For Career:
- Demonstrates security knowledge
- Shows Python proficiency
- Exhibits problem-solving skills
- Proves understanding of SDLC
- Relevant for DevSecOps roles

---

## 📈 Success Metrics

**Technical Metrics:**
- Detection rate: >90% for known vulnerabilities
- False positive rate: <15%
- Scan speed: >100 files per minute
- Code coverage: >80%

**User Experience:**
- Clear, actionable reports
- Easy installation (<5 minutes)
- Intuitive CLI
- Helpful error messages

**Learning Outcomes:**
- Deep understanding of security vulnerabilities
- Proficiency with SAST techniques
- Knowledge of security frameworks
- Experience with AST-based analysis

---

## 🔮 Future Vision

**Short-term (3-6 months):**
- Support for JavaScript and Java
- IDE plugins (VS Code, PyCharm)
- CI/CD integrations
- Community contributions

**Long-term (6-12 months):**
- ML-powered vulnerability prediction
- Cross-language dataflow analysis
- Web dashboard for team collaboration
- Commercial-grade accuracy and performance

**Dream Features:**
- Auto-fix suggestions (AI-powered)
- Integration with bug bounty platforms
- Real-time scanning in development
- Threat intelligence feeds