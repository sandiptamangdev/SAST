# SAST Learning Guide - Static Analysis Security Tool

## **Python & Security Concepts Required**

### **1. Python Fundamentals**
- File I/O operations (`open()`, `read()`, `write()`)
- Exception handling (`try/except/finally`)
- String manipulation and regex (`re` module)
- Working with modules and imports
- Command-line arguments (`argparse`, `sys.argv`)
- Path handling (`os.path`, `pathlib`)
- JSON/YAML parsing for config files

### **2. Static Analysis Concepts** ⭐ Critical
- **What is SAST?** - Analyzing code without executing it
- **Abstract Syntax Trees (AST)** - Python's `ast` module
  - Parsing Python code into nodes
  - Traversing AST to find patterns
  - Identifying function calls, imports, variables
- **Pattern Matching** - Detecting insecure code patterns
  - Regular expressions for quick scans
  - AST-based analysis for deep inspection
- **Control Flow Analysis** - Understanding code execution paths

### **3. Security Frameworks & Standards** ⭐ Essential
#### **OWASP Top 10**
- A01:2021 – Broken Access Control
- A02:2021 – Cryptographic Failures
- A03:2021 – Injection
- A04:2021 – Insecure Design
- A05:2021 – Security Misconfiguration
- A06:2021 – Vulnerable and Outdated Components
- A07:2021 – Identification and Authentication Failures
- A08:2021 – Software and Data Integrity Failures
- A09:2021 – Security Logging and Monitoring Failures
- A10:2021 – Server-Side Request Forgery (SSRF)

#### **CWE (Common Weakness Enumeration)**
- CWE-89: SQL Injection
- CWE-79: Cross-Site Scripting (XSS)
- CWE-502: Deserialization of Untrusted Data
- CWE-798: Use of Hard-coded Credentials
- CWE-327: Use of Broken Cryptographic Algorithm
- CWE-22: Path Traversal
- CWE-78: OS Command Injection

#### **MITRE ATT&CK Framework**
- Understanding tactics and techniques
- Mapping vulnerabilities to attack patterns
- Threat modeling concepts

### **4. Security Tool Integration** ⭐ Important
#### **Bandit**
```python
# Installing Bandit
pip install bandit

# Basic usage
bandit -r ./path/to/code -f json -o report.json

# Custom config
bandit -r ./code --configfile bandit.yaml
```
- Understanding Bandit's severity levels (LOW, MEDIUM, HIGH)
- Parsing Bandit JSON output
- Customizing Bandit plugins
- Handling false positives

#### **Pylint**
```python
# Installing Pylint
pip install pylint

# Basic usage
pylint your_file.py --output-format=json

# Disable specific checks
pylint --disable=C0111,R0903 your_file.py
```
- Understanding Pylint message categories (C, R, W, E, F)
- Integrating Pylint programmatically
- Custom Pylint checkers

#### **Flake8**
```python
# Installing Flake8
pip install flake8

# Basic usage
flake8 your_file.py --format=json

# With plugins
flake8 --install-hook git
```
- PEP 8 style guide compliance
- Plugin ecosystem (flake8-security)

### **5. Subprocess Management**
```python
import subprocess

# Running external tools
result = subprocess.run(
    ['bandit', '-r', 'code/', '-f', 'json'],
    capture_output=True,
    text=True,
    timeout=30
)

# Handling output
if result.returncode == 0:
    output = result.stdout
else:
    error = result.stderr
```
- Using `subprocess.run()`
- Handling timeouts and errors
- Parsing command output
- Security considerations (avoiding shell=True)

### **6. Python AST Module** ⭐ Advanced
```python
import ast

# Parse Python code
with open('file.py', 'r') as f:
    tree = ast.parse(f.read())

# Custom visitor pattern
class SecurityVisitor(ast.NodeVisitor):
    def visit_Call(self, node):
        # Check for dangerous function calls
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec', 'compile']:
                print(f"Dangerous function: {node.func.id}")
        self.generic_visit(node)

visitor = SecurityVisitor()
visitor.visit(tree)
```
- Understanding AST node types
- Implementing custom visitors
- Detecting specific code patterns
- Line number tracking

### **7. Report Generation**
#### **JSON Reports**
```python
import json

report = {
    "scan_date": "2025-12-15",
    "files_scanned": 10,
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "severity": "HIGH",
            "file": "app.py",
            "line": 42,
            "cwe": "CWE-89",
            "owasp": "A03:2021"
        }
    ]
}

with open('report.json', 'w') as f:
    json.dump(report, f, indent=2)
```

#### **HTML/PDF Reports**
```python
# Using Jinja2 for HTML templates
from jinja2 import Template

template = Template("""
<html>
<body>
    <h1>Security Report</h1>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability">
        <h2>{{ vuln.type }}</h2>
        <p>Severity: {{ vuln.severity }}</p>
    </div>
    {% endfor %}
</body>
</html>
""")

html = template.render(vulnerabilities=vulns)
```

### **8. Vulnerability Detection Patterns** ⭐ Critical

#### **SQL Injection Detection**
```python
# Insecure pattern
query = "SELECT * FROM users WHERE id = " + user_input

# AST detection
def check_sql_injection(node):
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            # Check if concatenating SQL queries
            return True
```

#### **Hard-coded Secrets**
```python
import re

# Regex patterns
SECRET_PATTERNS = {
    'api_key': r'api[_-]?key\s*=\s*["\']([^"\']+)["\']',
    'password': r'password\s*=\s*["\']([^"\']+)["\']',
    'token': r'token\s*=\s*["\']([^"\']+)["\']'
}

def find_secrets(code):
    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            findings.append({
                'type': secret_type,
                'value': match.group(1)
            })
    return findings
```

#### **Insecure Deserialization**
```python
# Dangerous patterns
import pickle
data = pickle.loads(untrusted_input)  # VULNERABLE

# Detection
dangerous_modules = ['pickle', 'marshal', 'shelve']
```

#### **Command Injection**
```python
# Insecure pattern
os.system("ls " + user_input)
subprocess.call("cat " + filename, shell=True)

# Detection in AST
def check_command_injection(node):
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in ['system', 'popen', 'exec']:
            return True
```

### **9. Configuration Management**
```python
import yaml

# config.yaml
config = {
    'scan_rules': {
        'enable_bandit': True,
        'enable_custom': True,
        'severity_threshold': 'MEDIUM'
    },
    'excluded_patterns': [
        '*.test.py',
        'migrations/*'
    ]
}

with open('config.yaml', 'w') as f:
    yaml.dump(config, f)
```

### **10. Logging & Debugging**
```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sast.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("Starting security scan...")
logger.warning("Potential vulnerability found")
logger.error("Failed to parse file")
```

---

## **Key Security Vulnerabilities to Detect**

### **1. Injection Vulnerabilities**
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- LDAP Injection (CWE-90)
- XPath Injection (CWE-643)

### **2. Cryptographic Issues**
- Weak algorithms (MD5, SHA1)
- Hard-coded encryption keys
- Insecure random number generation
- Missing encryption

### **3. Authentication & Authorization**
- Hard-coded passwords
- Weak password policies
- Missing authentication checks
- Insecure session management

### **4. Input Validation**
- Path traversal (CWE-22)
- XXE (XML External Entity)
- Unvalidated redirects
- Missing input sanitization

### **5. Error Handling**
- Information disclosure in error messages
- Improper exception handling
- Missing error logging

---

## **Learning Path Order**

### **Week 1: Python Fundamentals & Setup**
1. File I/O and exception handling
2. Working with modules and imports
3. Command-line argument parsing
4. Setting up virtual environment
5. Installing analysis tools (Bandit, Pylint, Flake8)

### **Week 2: Security Frameworks** ⭐
1. Study OWASP Top 10 (2021)
2. Understand CWE classification
3. Explore MITRE ATT&CK framework
4. Map vulnerabilities to frameworks
5. Create severity scoring system

### **Week 3: Tool Integration**
1. Integrate Bandit for security scanning
2. Add Pylint for code quality
3. Integrate Flake8 for style checking
4. Parse JSON outputs from tools
5. Aggregate results into unified format

### **Week 4: AST & Pattern Detection** ⭐
1. Learn Python AST basics
2. Implement custom AST visitors
3. Detect SQL injection patterns
4. Find hard-coded secrets
5. Identify command injection risks

### **Week 5: Report Generation**
1. Create JSON report structure
2. Add severity classification
3. Generate HTML reports with Jinja2
4. Add mitigation suggestions
5. Include code snippets as evidence

### **Week 6: Advanced Features**
1. Add configuration file support
2. Implement file exclusion patterns
3. Create custom security rules
4. Add false positive handling
5. Performance optimization

### **Week 7: Testing & Documentation**
1. Write unit tests for analyzers
2. Create integration tests
3. Test with vulnerable code samples
4. Write comprehensive documentation
5. Create usage examples

---

## **Practice Exercises**

### **Exercise 1: Detect Hard-coded Secrets**
```python
import re

def find_hardcoded_secrets(code):
    """
    Find API keys, passwords, and tokens in code
    """
    patterns = {
        'api_key': r'api[_-]?key\s*=\s*["\']([a-zA-Z0-9]{20,})["\']',
        'password': r'password\s*=\s*["\']([^"\']+)["\']'
    }
    
    findings = []
    for secret_type, pattern in patterns.items():
        for match in re.finditer(pattern, code, re.IGNORECASE):
            findings.append({
                'type': secret_type,
                'line': code[:match.start()].count('\n') + 1,
                'severity': 'HIGH'
            })
    return findings

# Test
test_code = '''
api_key = "sk_live_1234567890abcdef"
password = "admin123"
'''

print(find_hardcoded_secrets(test_code))
```

### **Exercise 2: SQL Injection Detection**
```python
import ast

class SQLInjectionDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []
    
    def visit_Call(self, node):
        # Check for string concatenation in SQL-related calls
        if self.is_sql_call(node):
            if self.has_string_concat(node):
                self.vulnerabilities.append({
                    'type': 'SQL Injection',
                    'line': node.lineno,
                    'severity': 'HIGH',
                    'cwe': 'CWE-89'
                })
        self.generic_visit(node)
    
    def is_sql_call(self, node):
        # Check if function name contains 'execute', 'query', etc.
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in ['execute', 'executemany', 'query']
        return False
    
    def has_string_concat(self, node):
        # Check if arguments contain string concatenation
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                return True
        return False

# Test
code = '''
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
'''

tree = ast.parse(code)
detector = SQLInjectionDetector()
detector.visit(tree)
print(detector.vulnerabilities)
```

### **Exercise 3: Command Injection Detection**
```python
import ast

class CommandInjectionDetector(ast.NodeVisitor):
    DANGEROUS_FUNCTIONS = {
        'os.system', 'os.popen', 'subprocess.call',
        'subprocess.Popen', 'commands.getoutput'
    }
    
    def __init__(self):
        self.findings = []
    
    def visit_Call(self, node):
        func_name = self.get_func_name(node)
        
        if func_name in self.DANGEROUS_FUNCTIONS:
            # Check if shell=True is used
            if self.uses_shell(node):
                self.findings.append({
                    'type': 'Command Injection',
                    'function': func_name,
                    'line': node.lineno,
                    'severity': 'CRITICAL',
                    'cwe': 'CWE-78'
                })
        
        self.generic_visit(node)
    
    def get_func_name(self, node):
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None
    
    def uses_shell(self, node):
        for keyword in node.keywords:
            if keyword.arg == 'shell':
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value is True
        return False

# Test
code = '''
import subprocess
subprocess.call("ls " + user_input, shell=True)
'''

tree = ast.parse(code)
detector = CommandInjectionDetector()
detector.visit(tree)
print(detector.findings)
```

---

## **Important Concepts Explained**

### **Why Use AST Instead of Regex?**
```python
# Regex can miss complex cases
code = """
query = "SELECT * FROM users WHERE id = " 
query += str(user_id)
cursor.execute(query)
"""
# AST can track variable flow and catch this!
```

### **Severity Scoring System**
```python
def calculate_severity(vuln):
    """
    Calculate severity based on multiple factors
    """
    base_severity = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 2
    }
    
    score = base_severity.get(vuln['severity'], 0)
    
    # Adjust based on exploitability
    if vuln.get('exploitable', False):
        score += 2
    
    # Adjust based on data sensitivity
    if vuln.get('affects_sensitive_data', False):
        score += 2
    
    return min(score, 10)
```

### **False Positive Handling**
```python
# Whitelist safe patterns
SAFE_PATTERNS = [
    r'cursor\.execute\("[^"]*", \(.*\)\)',  # Parameterized query
    r'hashlib\.sha256\(',  # Modern hash function
]

def is_false_positive(code_snippet):
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, code_snippet):
            return True
    return False
```

---

## **Common Pitfalls & Solutions**

### **1. Problem: Bandit produces too many false positives**
**Solution:**
```python
# Create custom Bandit config
# bandit.yaml
exclude_dirs:
  - '/test/'
  - '/tests/'
  - '/migrations/'

skips:
  - B101  # assert_used
  - B601  # paramiko_calls

# Use selective scanning
bandit -r code/ -ll -i  # Only HIGH and MEDIUM
```

### **2. Problem: Performance issues with large codebases**
**Solution:**
```python
# Parallelize scanning
from multiprocessing import Pool

def scan_file(filepath):
    # Scan single file
    return analyze(filepath)

with Pool(processes=4) as pool:
    results = pool.map(scan_file, file_list)
```

### **3. Problem: AST parsing fails on invalid syntax**
**Solution:**
```python
import ast

def safe_parse(code):
    try:
        return ast.parse(code)
    except SyntaxError as e:
        logger.warning(f"Syntax error: {e}")
        return None
    except Exception as e:
        logger.error(f"Parse error: {e}")
        return None
```

### **4. Problem: Difficult to map findings to frameworks**
**Solution:**
```python
# Create mapping dictionary
VULN_MAPPING = {
    'sql_injection': {
        'cwe': 'CWE-89',
        'owasp': 'A03:2021 - Injection',
        'mitre': 'T1190 - Exploit Public-Facing Application'
    },
    'hardcoded_secret': {
        'cwe': 'CWE-798',
        'owasp': 'A07:2021 - Identification Failures',
        'mitre': 'T1552.001 - Credentials In Files'
    }
}

def enrich_finding(vuln):
    mapping = VULN_MAPPING.get(vuln['type'], {})
    vuln.update(mapping)
    return vuln
```

---

## **Resources**

### **Security Standards**
1. [OWASP Top 10 (2021)](https://owasp.org/Top10/)
2. [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
3. [MITRE ATT&CK Framework](https://attack.mitre.org/)
4. [NIST Secure Coding Guide](https://www.nist.gov/)

### **Python Security**
1. [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security.html)
2. [Bandit Documentation](https://bandit.readthedocs.io/)
3. [Python AST Module Docs](https://docs.python.org/3/library/ast.html)
4. [OWASP Python Security Cheat Sheet](https://cheatsheetseries.owasp.org/)

### **SAST Tools**
1. Bandit - Python security linter
2. Semgrep - Multi-language static analysis
3. SonarQube - Comprehensive code quality
4. Snyk Code - Developer-first security

### **Learning Platforms**
1. [TryHackMe - Security Fundamentals](https://tryhackme.com/)
2. [HackTheBox - Web Security](https://www.hackthebox.com/)
3. [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
4. [Damn Vulnerable Python Application](https://github.com/anxolerd/dvpwa)

---

## **Testing Checklist**

### **Vulnerability Detection**
- [ ] SQL Injection detection works
- [ ] Hard-coded secrets are found
- [ ] Command injection is detected
- [ ] Weak cryptography is identified
- [ ] Path traversal is caught

### **Framework Mapping**
- [ ] CWE IDs are correct
- [ ] OWASP categories match
- [ ] MITRE techniques are accurate
- [ ] Severity scoring is consistent

### **Tool Integration**
- [ ] Bandit runs successfully
- [ ] Pylint output is parsed
- [ ] Flake8 results are captured
- [ ] All outputs are aggregated

### **Report Generation**
- [ ] JSON reports are valid
- [ ] HTML reports render correctly
- [ ] Severity is clearly indicated
- [ ] Mitigation advice is provided
- [ ] Code snippets are included

### **Edge Cases**
- [ ] Large files (>10MB)
- [ ] Files with syntax errors
- [ ] Empty files
- [ ] Binary files are skipped
- [ ] Timeout handling works