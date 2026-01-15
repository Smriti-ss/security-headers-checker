# Security Headers Checker

A Python tool that analyzes websites for missing security headers and provides a security score.

## What it does

This tool checks websites for essential security headers that protect against common web attacks like:
- Clickjacking
- XSS (Cross-Site Scripting)
- MIME type sniffing
- Man-in-the-middle attacks

## Features

- Scans 7 critical security headers
- Provides detailed explanations for each header
- Calculates overall security score
- Shows which headers are present/missing
- Easy to use command-line interface

## How to use

**Requirements:**
- Python 3.x
- requests library

**Installation:**
```bash
git clone https://github.com/Smriti-ss/security-headers-checker.git
cd security-headers-checker
pip install requests
```

**Usage:**
```bash
python security_checker.py https://example.com
```

## Example Output
```
============================================================
       SECURITY HEADERS CHECKER
============================================================

Security Headers Analysis for: https://google.com
Scan Time: 2026-01-15 00:12:49

✓ PRESENT HEADERS:
------------------------------------------------------------
  X-Frame-Options
    Value: SAMEORIGIN
    Purpose: Protects against clickjacking

✗ MISSING HEADERS:
------------------------------------------------------------
  Strict-Transport-Security
    Purpose: Enforces HTTPS connections
    
============================================================
SECURITY SCORE: 28.6%
============================================================
⚠️  WARNING: This site has weak security header configuration
```

## 🔍 Headers Checked

| Header | Purpose |
|--------|---------|
| Strict-Transport-Security | Enforces HTTPS connections |
| X-Content-Type-Options | Prevents MIME type sniffing |
| X-Frame-Options | Protects against clickjacking |
| X-XSS-Protection | Enables XSS filter in browsers |
| Content-Security-Policy | Controls resource loading |
| Referrer-Policy | Controls referrer information |
| Permissions-Policy | Controls browser features |

## Why I built this

Security headers are often overlooked but critical for web application security. I created this tool to quickly audit websites and raise awareness about these important security configurations.

## What I learned

- Working with HTTP headers and requests
- Security best practices for web applications
- Building CLI tools in Python
- Understanding common web vulnerabilities

## Connect with me

- LinkedIn: https://www.linkedin.com/in/smriti04/
---

⭐ If you found this useful, give it a star!
