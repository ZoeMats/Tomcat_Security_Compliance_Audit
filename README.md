READ ME

Apache Tomcat Security Compliance Scanner
A read-only configuration auditing tool for Apache Tomcat servers that evaluates security configurations against CIS Benchmark and OWASP guidelines.

Features
-Read-only operation (no configuration modifications)
-Four comprehensive security compliance checks
-Colour-coded console output with compliance indicators
-JSON and text export capabilities
-Verbose mode with detailed findings and recommendations
-Built-in help documentation

Installation - via bash
pip install -r requirements.txt

# Make script executable (Linux/macOS)
chmod +x tomcat-scan.py

Usage

Basic Scan
python tomcat-scan.py --target http://localhost:8080

Export Results
bashpython tomcat-scan.py --target http://localhost:8080 --export results.txt

Display Help
python tomcat-scan.py --help

## Security Checks

### 1. Information Leakage Prevention
**Configuration Files:** `server.xml`, `web.xml`
- Detects Server header version disclosure
- Identifies verbose error pages revealing stack traces or version information
- **Hardening:** Set `server=""` in Connector elements; configure `showServerInfo="false"` and `showReport="false"` in ErrorReportValve

### 2. HTTPS Enforcement
**Configuration Files:** `server.xml`, `web.xml`
- Validates presence of HTTPS/SSL connectors
- Verifies encrypted communication enforcement
- **Hardening:** Configure SSL/TLS connector in `server.xml`; add `<security-constraint>` with `<transport-guarantee>CONFIDENTIAL</transport-guarantee>` in `web.xml`

### 3. Manager/Host-Manager Access Controls
**Configuration File:** `context.xml` (in manager application directories)
- Checks for IP-based access restrictions on management interfaces
- Validates RemoteAddrValve configuration
- **Hardening:** Implement RemoteAddrValve with allowed IP restrictions; remove unused manager applications to reduce attack surface

### 4. Password Encryption
**Configuration File:** `tomcat-users.xml`
- Detects plaintext passwords in user definitions
- Validates cryptographic hashing implementation
- **Hardening:** Configure password digests using SHA-256 or stronger algorithms; update credentials to use hashed values

## Example Output
[CHECK] Information Leakage Prevention ............ NON-COMPLIANT
[CHECK] HTTPS Enforcement ......................... NON-COMPLIANT
[CHECK] Manager Access Controls ................... NON-COMPLIANT
[CHECK] Password Encryption ....................... NON-COMPLIANT

COMPLIANCE SUMMARY
======================================================================
Total Checks:        4
Compliant:           0
Non-Compliant:       4
Partial:             0

Compliance Rate:     0%


## Project Structure
```
tomcat-compliance-scanner/
├── tomcat_scanner/           # Main package directory
│   ├── __init__.py          # Package initialization
│   ├── scanner.py           # Core scanner orchestration
│   ├── checks.py            # Security check implementations
│   ├── reporter.py          # Output formatting and export
│   └── config.py            # Configuration constants
├── tomcat-scan.py           # Command-line entry point
├── requirements.txt         # Python dependencies
└── README.md               # This file

Requirements

Python 3.7 or higher
Access to Tomcat installation directory for configuration file analysis (ideally Apache Tomcat 11.0.4)
Root or appropriate file permissions to read Tomcat configuration files

License
Educational/Academic Use