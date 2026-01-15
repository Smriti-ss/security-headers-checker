import requests
import sys
from datetime import datetime

# Security headers we want to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'Enforces HTTPS connections',
    'X-Content-Type-Options': 'Prevents MIME type sniffing',
    'X-Frame-Options': 'Protects against clickjacking',
    'X-XSS-Protection': 'Enables XSS filter in browsers',
    'Content-Security-Policy': 'Controls resource loading',
    'Referrer-Policy': 'Controls referrer information',
    'Permissions-Policy': 'Controls browser features'
}

def check_headers(url):
    """Check security headers for a given URL"""
    
    print(f"\n{'='*60}")
    print(f"Security Headers Analysis for: {url}")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    try:
        # Make request to the URL
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        present = []
        missing = []
        
        # Check each security header
        for header, description in SECURITY_HEADERS.items():
            if header in headers:
                present.append((header, headers[header], description))
            else:
                missing.append((header, description))
        
        # Display results
        print("✓ PRESENT HEADERS:")
        print("-" * 60)
        if present:
            for header, value, desc in present:
                print(f"  {header}")
                print(f"    Value: {value}")
                print(f"    Purpose: {desc}\n")
        else:
            print("  None found\n")
        
        print("✗ MISSING HEADERS:")
        print("-" * 60)
        if missing:
            for header, desc in missing:
                print(f"  {header}")
                print(f"    Purpose: {desc}\n")
        else:
            print("  All security headers are present!\n")
        
        # Calculate security score
        score = (len(present) / len(SECURITY_HEADERS)) * 100
        print(f"{'='*60}")
        print(f"SECURITY SCORE: {score:.1f}%")
        print(f"{'='*60}\n")
        
        # Recommendations
        if score < 50:
            print("⚠️  WARNING: This site has weak security header configuration")
        elif score < 80:
            print("⚠️  MODERATE: Consider adding missing security headers")
        else:
            print("✓ GOOD: Strong security header configuration")
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Could not connect to {url}")
        print(f"Details: {e}")

def main():
    print("\n" + "="*60)
    print("       SECURITY HEADERS CHECKER")
    print("="*60)
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("\nEnter website URL (e.g., https://example.com): ")
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    check_headers(url)

if __name__ == "__main__":
    main()