
# 🔐 EnvGuard — Secret & Sensitive File Scanner

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-16%20passed-brightgreen.svg?style=flat)](#testing)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](#license)
[![Git](https://img.shields.io/badge/Git-Pre--Commit-F05032.svg?style=flat&logo=git&logoColor=white)](https://git-scm.com/)

> A lightweight CLI security tool that scans software projects for potential secrets and sensitive files before they reach GitHub.

---

## 🚀 Overview

Accidentally committing an API key, password, token, private key, or `.env` file can create a serious security risk.

**EnvGuard** helps developers detect these issues before they are committed by scanning project files and optionally integrating directly with Git's pre-commit workflow.

It supports both:

- 🔍 One-off project scans
- 🪝 Automated Git pre-commit protection

---

## 🏗️ Architecture

```text
                         ENVGUARD
                            │
                            ▼
                     Select Project
                            │
                            ▼
                       File Scanner
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
        Secret Detection        Sensitive Files
                │                       │
                └───────────┬───────────┘
                            ▼
                       Risk Engine
                            │
                            ▼
                         Reporter
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
        Terminal Report           JSON Report
````

### Processing Pipeline

```text
Scanner
   ↓
Detector
   ↓
Rules
   ↓
Finding
   ↓
Risk Classification
   ↓
Reporter
```

Each finding contains:

```text
File
Line
Rule
Severity
Description
Masked matched text
```

---

## ✨ Features

### 🔍 Recursive Project Scanner

Scans project directories recursively while automatically excluding common generated or dependency directories:

```text
.git/
node_modules/
venv/
.venv/
__pycache__/
target/
```

### ⚠️ Sensitive File Detection

Detects potentially sensitive files independently of their contents:

```text
.env
.env.*
credentials.json
secrets.yaml
id_rsa
*.pem
*.pfx
*.p12
.npmrc
.netrc
```

### 🧠 Rule-Based Secret Detection

EnvGuard includes detection rules for:

* AWS access keys
* AWS secret keys
* Private key blocks
* Generic API keys
* OpenAI-style keys
* Slack tokens
* GitHub tokens
* JWTs
* Hardcoded passwords
* Database connection strings
* Generic secrets
* Suspicious environment-variable assignments

Rules are defined separately in `envguard/rules.py`, allowing new detection patterns to be added without changing the scanner or detector.

### 🚦 Risk Classification

Findings are classified into four levels:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

The final report provides a severity summary.

### 🩹 Secret Masking

EnvGuard never displays the complete value of a detected secret.

Example:

```text
matched: sk-f***********************
```

This prevents the security scanner itself from exposing the credential it detected.

### 🪝 Git Pre-Commit Protection

EnvGuard can scan staged files automatically before a Git commit.

Commits containing **HIGH or CRITICAL findings**, or sensitive files, can be blocked.

### 🙈 `.envguardignore`

Projects can exclude specific files or directories from scanning.

Example:

```text
tests/
examples/
docs/
```

### 📊 JSON Reporting

Machine-readable reports can be generated using:

```bash
python main.py . --json
```

---

## 🛠️ Technology Stack

| Technology                  | Purpose                         |
| --------------------------- | ------------------------------- |
| **Python**                  | Core application                |
| **Python Standard Library** | File handling, regex, JSON, CLI |
| **pytest**                  | Automated testing               |
| **Git**                     | Version control                 |
| **Git Hooks**               | Pre-commit security scanning    |

**Runtime dependencies:** None

EnvGuard uses only the Python standard library at runtime.

---

## 📁 Project Structure

```text
EnvGuard/
│
├── envguard/
│   ├── __init__.py
│   ├── scanner.py
│   ├── detector.py
│   ├── rules.py
│   ├── reporter.py
│   └── utils.py
│
├── hooks/
│   └── pre-commit
│
├── tests/
│   ├── ...
│   └── ...
│
├── examples/
│   └── vulnerable-project/
│       ├── config.py
│       └── .env.example
│
├── main.py
├── install_hook.py
├── requirements.txt
├── .envguardignore
├── .gitignore
└── README.md
```

---

## 🚦 Installation

### 1. Clone the Repository

```bash
git clone <https://github.com/pashvithareddy-debug/EnvGuard/>
cd EnvGuard
```

### 2. Install Test Dependencies

```bash
pip install -r requirements.txt
```

> EnvGuard itself has zero third-party runtime dependencies. `requirements.txt` is used for the test suite.

---

## 💻 Usage

### Scan the Current Directory

```bash
python main.py .
```

### Scan a Specific Project

```bash
python main.py ./my-project
```

### Show Only HIGH and CRITICAL Findings

```bash
python main.py . --severity high
```

### Generate JSON Output

```bash
python main.py . --json
```

### Scan Git-Staged Files

```bash
python main.py . --staged
```

### Configure the Failure Threshold

```bash
python main.py . --fail-on critical
```

---

## 📊 Example Output

```text
EnvGuard Security Scan
────────────────────────────────────────
Root: examples/vulnerable-project
Files scanned: 3  |  skipped: 0

⚠ SENSITIVE FILES
  .env.example

FINDINGS
────────────────────────────────────────

config.py
  Line 9     [CRITICAL] AWS_ACCESS_KEY_ID
             Possible AWS Access Key ID
             matched: AKIA****************

  Line 13    [HIGH] GENERIC_API_KEY
             Possible API key assignment
             matched: api_************************

  Line 19    [HIGH] PASSWORD_ASSIGNMENT
             Hardcoded password assignment
             matched: pass********************

SECURITY SUMMARY
────────────────────────────────────────
LOW      : 6
MEDIUM   : 0
HIGH     : 6
CRITICAL : 1

Sensitive files: 1
Total findings: 13
```

The bundled example project contains **fake credentials only** and is intended for testing.

Run:

```bash
python main.py examples/vulnerable-project
```

---

## 🔎 Detection Rules

| Rule                        | Severity | Description                                 |
| --------------------------- | -------- | ------------------------------------------- |
| `AWS_ACCESS_KEY_ID`         | CRITICAL | Possible AWS Access Key ID                  |
| `AWS_SECRET_ACCESS_KEY`     | CRITICAL | Possible AWS Secret Access Key              |
| `PRIVATE_KEY_BLOCK`         | CRITICAL | Embedded PEM/SSH private key                |
| `GENERIC_API_KEY`           | HIGH     | API key assignment                          |
| `OPENAI_STYLE_KEY`          | HIGH     | OpenAI-style `sk-...` key                   |
| `SLACK_TOKEN`               | HIGH     | Slack token                                 |
| `GITHUB_TOKEN`              | HIGH     | GitHub personal access token                |
| `DB_CONNECTION_STRING`      | HIGH     | Database connection string with credentials |
| `PASSWORD_ASSIGNMENT`       | HIGH     | Hardcoded password assignment               |
| `JWT_TOKEN`                 | MEDIUM   | JSON Web Token                              |
| `GENERIC_SECRET`            | MEDIUM   | Generic secret/token assignment             |
| `SUSPICIOUS_ENV_ASSIGNMENT` | LOW      | Suspicious environment-style assignment     |

New rules can be added in:

```text
envguard/rules.py
```

without modifying the scanner or detector.

---

## 🗂️ Sensitive Files

EnvGuard can identify sensitive files based on their names or extensions, including:

```text
.env
.env.*
credentials.json
secrets.yaml
id_rsa
*.pem
*.pfx
*.p12
.npmrc
.netrc
```

This detection is performed independently of the file's contents.

---

## 🙈 `.envguardignore`

Create a `.envguardignore` file in the project root to exclude paths from scanning.

Example:

```text
tests/
examples/
docs/
```

Comments can be added using `#`:

```text
# Test fixtures
tests/

# Documentation examples
docs/
```

---

## 🪝 Git Integration

Install the pre-commit hook:

```bash
python install_hook.py
```

This installs:

```text
hooks/pre-commit
```

into:

```text
.git/hooks/pre-commit
```

After installation, every Git commit can trigger an EnvGuard scan against the **staged files**.

Example:

```text
$ git commit -m "add configuration"

EnvGuard Security Scan
────────────────────────────────────────

Scanning staged files...

⚠ CRITICAL
AWS_ACCESS_KEY_ID detected in config.py:9

Commit blocked by EnvGuard.

Remove or mask the sensitive content before committing.
```

The hook blocks commits containing:

* HIGH findings
* CRITICAL findings
* Sensitive files

In a genuine emergency, Git can bypass hooks using:

```bash
git commit --no-verify
```

> Bypassing the security hook should be used carefully.

---

## 🧪 Testing

Run the complete test suite:

```bash
pytest tests/ -v
```

Current result:

```text
16 passed
```

Tests cover areas including:

* Rule integrity
* Valid-file scanning
* Sensitive-file detection
* API-key detection
* Password detection
* Private-key detection
* Excluded directories
* `.envguardignore`
* Empty projects
* Multiple secrets
* Secret masking
* Correct line numbers

---

## ⚠️ Limitations

EnvGuard is intentionally lightweight and currently uses regex-based detection.

### Detection Limitations

It may:

* Miss cleverly obfuscated secrets
* Produce false positives
* Miss random high-entropy secrets without recognizable patterns

### Git History

EnvGuard scans current working-tree or staged file contents.

It does **not** currently scan Git history.

Therefore, if a secret was committed in the past and later removed, EnvGuard will not automatically detect it.

### No Entropy Analysis

The current implementation does not use entropy-based detection for completely random credential strings.

---

## 🗺️ Future Improvements

Possible future versions could include:

* [ ] Entropy-based secret detection
* [ ] Provider-specific credential validation
* [ ] Git history scanning
* [ ] Inline suppression comments
* [ ] Project-level configuration file
* [ ] Custom rule configuration
* [ ] Additional secret providers
* [ ] Improved false-positive detection

---

## 🔐 Security Philosophy

EnvGuard follows a simple principle:

> **Detect early. Mask secrets. Block risky commits.**

The goal is not to guarantee that every secret will be detected, but to provide developers with an additional security layer before sensitive information reaches version control.

---

## 📌 Project Type

**Small Developer Security Tool**

Built to practice:

```text
Python
Regex
File Systems
Cybersecurity
Git
Git Hooks
CLI Development
JSON
Testing
Software Engineering
```

---

## 📄 License

MIT License

---

<div align="center">

<div align="center">

### 🔐 EnvGuard

**Detect secrets before they reach GitHub.**

Built as a practical cybersecurity and developer-tool project.

</div>
```


