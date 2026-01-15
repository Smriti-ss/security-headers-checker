import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

import requests
from requests.exceptions import RequestException


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 3,
        "description": "Enforces HTTPS via HSTS."
    },
    "Content-Security-Policy": {
        "weight": 4,
        "description": "Mitigates XSS and content injection."
    },
    "X-Frame-Options": {
        "weight": 2,
        "description": "Mitigates clickjacking."
    },
    "X-Content-Type-Options": {
        "weight": 1,
        "description": "Prevents MIME-sniffing."
    },
    "Referrer-Policy": {
        "weight": 1,
        "description": "Controls referrer info leakage."
    },
    "Permissions-Policy": {
        "weight": 1,
        "description": "Restricts browser features (camera, mic, etc.)."
    }
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def evaluate_headers(resp_headers: Dict[str, str]) -> Tuple[Dict[str, Any], float]:
    """
    Returns:
      results: dict with found/missing + notes
      score_percent: float in [0, 100]
    """
    # Make header lookup case-insensitive
    headers_ci = {k.lower(): v for k, v in resp_headers.items()}

    total_weight = sum(v["weight"] for v in SECURITY_HEADERS.values())
    earned_weight = 0

    found = []
    missing = []

    for header, meta in SECURITY_HEADERS.items():
        key = header.lower()
        if key in headers_ci:
            earned_weight += meta["weight"]
            found.append({
                "header": header,
                "value": headers_ci[key],
                "weight": meta["weight"],
                "description": meta["description"],
                "notes": []
            })
        else:
            missing.append({
                "header": header,
                "weight": meta["weight"],
                "description": meta["description"],
                "notes": ["Missing header"]
            })

    score_percent = round((earned_weight / total_weight) * 100, 1) if total_weight else 0.0

    results = {
        "summary": {
            "found_count": len(found),
            "missing_count": len(missing),
            "total_headers_checked": len(SECURITY_HEADERS),
            "earned_weight": earned_weight,
            "total_weight": total_weight,
        },
        "found": found,
        "missing": missing,
    }
    return results, score_percent


def build_report(
    url: str,
    final_url: str,
    status_code: int,
    resp_headers: Dict[str, str],
    eval_results: Dict[str, Any],
    score_percent: float,
    args: argparse.Namespace
) -> Dict[str, Any]:
    return {
        "meta": {
            "tool": "security-headers-checker",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "args": {
                "timeout": args.timeout,
                "verify_tls": not args.no_verify,
                "follow_redirects": args.follow_redirects,
                "user_agent": args.user_agent,
            }
        },
        "target": {
            "input_url": url,
            "final_url": final_url,
            "status_code": status_code,
        },
        "response_headers": dict(resp_headers),  # raw headers (as returned)
        "analysis": {
            "score_percent": score_percent,
            "rating": rating_from_score(score_percent),
            "details": eval_results,
        }
    }


def rating_from_score(score: float) -> str:
    if score >= 85:
        return "Strong"
    if score >= 60:
        return "Moderate"
    return "Weak"


def print_human(report: Dict[str, Any]) -> None:
    target = report["target"]
    analysis = report["analysis"]
    details = analysis["details"]["summary"]

    print(f"\n🔎 Scanning: {target['input_url']}")
    if target["final_url"] != target["input_url"]:
        print(f"↪️  Final URL: {target['final_url']}")
    print(f"📡 Status: {target['status_code']}")

    print(f"\n✅ Score: {analysis['score_percent']}%  ({analysis['rating']})")
    print(
        f"Headers found: {details['found_count']} | Missing: {details['missing_count']} "
        f"| Total checked: {details['total_headers_checked']}"
    )

    print("\n✅ Found headers:")
    for item in report["analysis"]["details"]["found"]:
        print(f"  - {item['header']}")

    print("\n❌ Missing headers:")
    for item in report["analysis"]["details"]["missing"]:
        print(f"  - {item['header']}")

    print("")  # final newline


def write_json(report: Dict[str, Any], path: str, pretty: bool) -> None:
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(report, f, indent=2, ensure_ascii=False)
        else:
            json.dump(report, f, separators=(",", ":"), ensure_ascii=False)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check a URL for common HTTP security headers and output a score/report."
    )
    p.add_argument("url", help="Target URL (e.g., https://example.com)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    p.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    p.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    p.add_argument("--user-agent", default="security-headers-checker/1.0", help="Custom User-Agent")
    p.add_argument("--json", dest="json_path", help="Write JSON report to a file (e.g., report.json)")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON output (when using --json)")
    p.add_argument("--quiet", action="store_true", help="Minimal console output")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    url = normalize_url(args.url)

    headers = {"User-Agent": args.user_agent}

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=args.timeout,
            verify=not args.no_verify,
            allow_redirects=args.follow_redirects,
        )
    except RequestException as e:
        print(f"❌ Request failed: {e}", file=sys.stderr)
        return 2

    # requests stores headers in a case-insensitive dict-like object; convert cleanly
    resp_headers = dict(resp.headers)
    eval_results, score_percent = evaluate_headers(resp_headers)

    report = build_report(
        url=url,
        final_url=str(resp.url),
        status_code=resp.status_code,
        resp_headers=resp_headers,
        eval_results=eval_results,
        score_percent=score_percent,
        args=args
    )

    if args.json_path:
        write_json(report, args.json_path, args.pretty)
        if not args.quiet:
            print(f"🧾 JSON report written to: {args.json_path}")

    if not args.quiet:
        print_human(report)
    else:
        # quiet mode: just print score
        print(f"{score_percent}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
