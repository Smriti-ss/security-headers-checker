# Security Headers Checker

A professional-grade Python tool that analyzes websites for missing security headers, provides weighted scoring, and exports detailed JSON reports.

## What it does

This tool checks websites for essential security headers that protect against common web attacks:
- **XSS (Cross-Site Scripting)**
- **Clickjacking**
- **MIME type sniffing**
- **Man-in-the-middle attacks**
- **Content injection**

## Features

- **Weighted scoring system** - Critical headers like CSP have higher weight
- **JSON export** - Generate machine-readable reports for automation
- **Multiple output formats** - Human-readable console output or JSON
- **Flexible CLI options** - Timeout, redirects, custom user-agent, and more
- **Professional ratings** - Strong/Moderate/Weak based on security posture
- **Quiet mode** - Perfect for CI/CD pipelines

## Installation

**Requirements:**
- Python 3.7+
- requests library

**Setup:**
```bash
git clone https://github.com/Smriti-ss/security-headers-checker.git
cd security-headers-checker
pip install requests
```

## Usage

### Basic scan:
```bash
python security_checker.py https://example.com
```

### Export to JSON:
```bash
python security_checker.py https://example.com --json report.json --pretty
```

### Follow redirects:
```bash
python security_checker.py http://example.com --follow-redirects
```

### Quiet mode (just the score):
```bash
python security_checker.py https://example.com --quiet
```

### All options:
```bash
python security_checker.py https://example.com \
  --timeout 15 \
  --follow-redirects \
  --json report.json \
  --pretty
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--timeout` | Request timeout in seconds | 10 |
| `--no-verify` | Disable TLS certificate verification | False |
| `--follow-redirects` | Follow HTTP redirects | False |
| `--user-agent` | Custom User-Agent string | security-headers-checker/1.0 |
| `--json` | Export report to JSON file | None |
| `--pretty` | Pretty-print JSON output | False |
| `--quiet` | Minimal output (score only) | False |

## Example Output

### Console Output:
```
🔎 Scanning: https://twitter.com
↪️  Final URL: https://twitter.com/
📡 Status: 301

Score: 83.3%  (Moderate)
Headers found: 4 | Missing: 2 | Total checked: 6

Found headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options

Missing headers:
  - Referrer-Policy
  - Permissions-Policy
```

### JSON Output:
The tool can export detailed JSON reports containing:
- Scan metadata and configuration
- Target URL information
- All response headers
- Detailed analysis with weights
- Security score and rating

## Headers Checked (with weights)

| Header | Weight | Purpose |
|--------|--------|---------|
| **Content-Security-Policy** | 4 | Mitigates XSS and content injection |
| **Strict-Transport-Security** | 3 | Enforces HTTPS via HSTS |
| **X-Frame-Options** | 2 | Mitigates clickjacking |
| **X-Content-Type-Options** | 1 | Prevents MIME-sniffing |
| **Referrer-Policy** | 1 | Controls referrer info leakage |
| **Permissions-Policy** | 1 | Restricts browser features |

**Total Weight:** 12 points

## Scoring System

- **Strong (85%+):** Excellent security header configuration
- **Moderate (60-84%):** Good security, some improvements possible
- **Weak (<60%):** Significant security headers missing

## Why I built this

Security headers are often overlooked but critical for web application security. I created this tool to:
- Quickly audit websites and APIs
- Integrate security checks into CI/CD pipelines
- Raise awareness about security header best practices
- Provide actionable insights with weighted scoring

## What I learned

- **Security best practices:** Understanding the role of each security header
- **Python development:** Type hints, argparse, modular design
- **CLI tool design:** Building user-friendly command-line interfaces
- **Data formats:** JSON export for automation and integration
- **Web security:** Common vulnerabilities and mitigation strategies

## Contributing

Found a bug or have a feature request? Feel free to open an issue!

## 📄 License

This project is open source and available for educational purposes.

---

## Connect with me

- LinkedIn: https://www.linkedin.com/in/smriti04/
---

⭐ If you found this useful, give it a star!
