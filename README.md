# 🛡️ CI/CD Security Gatekeeper & Static Analyzer (DevSecOps)

A Python-based DevSecOps security tool designed to act as a local CI/CD gatekeeper. It automatically scans source code for hardcoded secrets/API keys and checks project dependencies (`requirements.txt`) against the open-source **OSV Vulnerability Database**.

---

## 🎯 Features

* **Static Secret Detection (SAST):** Scans `.py` source files for leaked AWS keys, generic API secrets, and private keys using Regex.
* **Software Supply Chain Security (SCA):** Queries the public OSV API to check third-party libraries against real-world CVE databases.
* **Pipeline Blocking:** Returns exit code `1` when high-risk findings are detected to automatically halt CI/CD builds or Git commits.

---

## 📁 Repository Structure

```text
devsecops-security-gatekeeper/
├── app.py              # Sample developer application code
├── requirements.txt    # Project dependencies list
├── gatekeeper.py       # Core DevSecOps security scanner engine
└── README.md           # Documentation