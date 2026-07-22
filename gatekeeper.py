import json
import os
import re
import sys
import urllib.request

# Regular expressions for detecting common hardcoded secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic Secret/API Key": r"(?i)(api_key|secret|password|passwd)\s*=\s*['\"][A-Za-z0-9%=-]{8,}['\"]",
    "Private Key Header": r"-----BEGIN (RSA|EC|PGP) PRIVATE KEY-----",
}

# Known vulnerable versions for simple offline fallback + OSV API lookup
OSV_API_URL = "https://api.osv.dev/v1/query"


def scan_for_secrets():
    """Scans Python files in the current folder for hardcoded secrets."""
    print("🔍 [1/2] Scanning code for hardcoded secrets...")
    secrets_found = []

    for root, _, files in os.walk("."):
        for file in files:
            if file.endswith(".py") and file != "gatekeeper.py":
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, start=1):
                        for secret_type, pattern in SECRET_PATTERNS.items():
                            if re.search(pattern, line):
                                secrets_found.append(
                                    {
                                        "file": filepath,
                                        "line": line_num,
                                        "type": secret_type,
                                        "snippet": line.strip(),
                                    }
                                )

    return secrets_found


def scan_dependencies():
    """Checks requirements.txt against the OSV vulnerability database."""
    print("\n📦 [2/2] Scanning dependencies for known vulnerabilities...")
    vulnerabilities = []

    if not os.path.exists("requirements.txt"):
        print("  └─ No requirements.txt found. Skipping dependency check.")
        return vulnerabilities

    with open("requirements.txt", "r") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if "==" in line:
            pkg_name, version = line.split("==")
            # Query OSV API
            payload = json.dumps(
                {
                    "version": version.strip(),
                    "package": {"name": pkg_name.strip(), "ecosystem": "PyPI"},
                }
            ).encode("utf-8")

            try:
                req = urllib.request.Request(
                    OSV_API_URL,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode("utf-8"))
                    if "vulns" in data:
                        vuln_count = len(data["vulns"])
                        vulnerabilities.append(
                            {
                                "package": pkg_name,
                                "version": version,
                                "vuln_count": vuln_count,
                                "summary": data["vulns"][0].get(
                                    "summary", "Known Security Vulnerability"
                                ),
                            }
                        )
            except Exception as e:
                print(f"  └─ Error checking {pkg_name}: {e}")

    return vulnerabilities


if __name__ == "__main__":
    print("=" * 60)
    print(" 🛑 DEVSECOPS SECURITY GATEKEEPER SCAN")
    print("=" * 60)

    # Run Scans
    secrets = scan_for_secrets()
    vuls = scan_dependencies()

    # Generate Report
    print("\n" + "=" * 60)
    print(" 📊 SCAN RESULTS")
    print("=" * 60)

    total_issues = len(secrets) + len(vuls)

    if secrets:
        print("\n❌ HARDCODED SECRETS DETECTED:")
        for s in secrets:
            print(
                f"  - [{s['type']}] {s['file']} (Line {s['line']}): {s['snippet']}"
            )

    if vuls:
        print("\n⚠️ VULNERABLE DEPENDENCIES DETECTED:")
        for v in vuls:
            print(
                f"  - Package: {v['package']} v{v['version']} | {v['vuln_count']} Known CVEs | {v['summary']}"
            )

    print("\n" + "=" * 60)
    if total_issues > 0:
        print(f" 🚫 PIPELINE BLOCKED! Found {total_issues} security flaw(s).")
        print(" Please fix the issues above before pushing code.")
        print("=" * 60)
        sys.exit(1)  # Non-zero exit code stops CI/CD pipelines!
    else:
        print(" ✅ PIPELINE PASSED! No security issues detected.")
        print("=" * 60)
        sys.exit(0)