Website Security Scanner

A comprehensive Python-based security scanner that checks websites for common vulnerabilities including open ports, SSL issues, security headers, SQL injection, and XSS vulnerabilities.

Features

· Port Scanning: Scans common web ports and customizable ranges
· SSL Certificate Validation: Checks certificate validity, expiration, and weak protocols
· Security Headers Analysis: Verifies presence and proper configuration of security headers
· SQL Injection Testing: Tests for both error-based and time-based SQL injection vulnerabilities
· XSS Testing: Detects reflected and DOM-based XSS vulnerabilities
· Additional Security Checks: Includes CORS misconfiguration, sensitive path detection, and clickjacking tests
· Multiple Output Formats: Console (color-coded), JSON, and HTML reports

Installation

1. Clone or download the project files
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

Requirements

The script requires the following Python packages:

· requests>=2.28.0
· colorama>=0.4.6
· scapy>=2.5.0
· beautifulsoup4>=4.12.0
· lxml>=4.9.0

Usage

Run the script from the command line:

```bash
python security_scanner.py
```

You will be prompted to:

1. Enter the website URL to scan
2. Select output format (console, json, or html)

Output Formats

· Console: Color-coded output with vulnerability severity indicators
· JSON: Machine-readable format for integration with other tools
· HTML: Professional report format suitable for sharing with stakeholders

What It Checks

1. Port Scanning

· Scans ports 1-1024 plus common web ports (80, 443, 8080, 8443, etc.)
· Uses parallel scanning for faster results

2. SSL Certificate Analysis

· Validates certificate chain
· Checks for weak protocols (SSLv2, SSLv3, TLS1.0)
· Identifies self-signed certificates
· Reports expiration information

3. Security Headers Verification

· Content-Security-Policy (with best practices validation)
· X-Frame-Options
· Strict-Transport-Security
· X-Content-Type-Options
· X-XSS-Protection
· Referrer-Policy
· Permissions-Policy

4. SQL Injection Testing

· Error-based SQLi detection
· Time-based blind SQLi detection
· Multiple payload types tested

5. XSS Testing

· Reflected XSS detection
· DOM-based XSS detection
· Tests both query parameters and URL fragments

6. Additional Security Checks

· CORS misconfiguration testing
· Sensitive path discovery (e.g., /.git/, /admin/)
· Clickjacking vulnerability assessment

Example Output

```
============================================================
SECURITY SCAN REPORT
============================================================
Target URL: https://example.com
Scan date: 2023-08-15 14:30:25
============================================================

1. OPEN PORTS SCAN
----------------------------------------
Open ports found: 80, 443, 8080

2. SSL CERTIFICATE CHECK
----------------------------------------
SSL certificate is valid.
Issuer: Let's Encrypt
Subject: example.com
Expiry date: 2023-11-15
Days until expiry: 92
Weak protocols supported: TLSv1

3. SECURITY HEADERS CHECK
----------------------------------------
Content-Security-Policy: default-src 'self' (WARNING - CSP allows unsafe-inline)
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000 (WARNING - HSTS missing includeSubDomains directive)
...
```

Important Notes

· This tool is for educational and authorized security testing only
· Always obtain proper permission before scanning any website
· Some tests may be detected by WAFs (Web Application Firewalls)
· Results should be verified manually as false positives/negatives may occur

Disclaimer

This tool is provided for educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have permission to scan the target website.

License

This project is open source and available under the MIT License.
