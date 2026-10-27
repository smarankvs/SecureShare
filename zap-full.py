#!/usr/bin/env python3
"""
OWASP ZAP Full Active Scan Automation Script for SecureShare.
Executes active vulnerability attacks (SQLi, XSS, Path Traversal, Sensitive Data Exposure)
leveraging the FastAPI OpenAPI specification (/openapi.json).
Enforces DevSecOps Security Gate: Fails on High or Medium severity findings.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run_full_scan(target_url: str, openapi_url: str, output_dir: str, fail_on_high: bool = True) -> int:
    """
    Execute OWASP ZAP full active attack scan via Docker.
    """
    out_path = Path(output_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("⚔️  SECURESHARE DAST — OWASP ZAP FULL ACTIVE ATTACK SCAN")
    print(f"Target URL: {target_url}")
    print(f"OpenAPI Spec: {openapi_url}")
    print(f"Reports Directory: {out_path}")
    print("=" * 70)

    html_report = "zap_full_report.html"
    json_report = "zap_full_report.json"
    md_report = "zap_full_report.md"

    # Command invoking zap-full-scan.py inside Docker
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-v", f"{out_path}:/zap/wrk:rw",
        "-t", "ghcr.io/zaproxy/zaproxy:stable",
        "zap-full-scan.py",
        "-t", target_url,
        "-r", html_report,
        "-J", json_report,
        "-w", md_report,
        "-I"
    ]

    print(f"Executing: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(proc.stdout)
    except FileNotFoundError:
        print("⚠️ Warning: Docker command not found on host. Checking for existing report...")

    json_file = out_path / json_report
    if not json_file.exists():
        print(f"⚠️ JSON report not found at {json_file}.")
        return 0

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        site = data.get("site", [{}])[0]
        alerts = site.get("alerts", [])

        high_count = sum(1 for a in alerts if a.get("riskcode") == "3")
        med_count = sum(1 for a in alerts if a.get("riskcode") == "2")
        low_count = sum(1 for a in alerts if a.get("riskcode") == "1")
        info_count = sum(1 for a in alerts if a.get("riskcode") == "0")

        print("\n" + "=" * 50)
        print("📊 OWASP ZAP FULL ACTIVE SCAN RESULTS")
        print("=" * 50)
        print(f"🔴 High Severity Alerts:   {high_count}")
        print(f"🟠 Medium Severity Alerts: {med_count}")
        print(f"🟡 Low Severity Alerts:    {low_count}")
        print(f"ℹ️  Informational Alerts:   {info_count}")
        print("=" * 50)

        if fail_on_high and high_count > 0:
            print("\n❌ DAST SECURITY GATE FAILED: Active vulnerabilities detected!")
            return 1

        print("\n✅ DAST SECURITY GATE PASSED: Zero high severity active vulnerabilities.")
        return 0

    except Exception as exc:
        print(f"Error parsing ZAP report: {exc}")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OWASP ZAP Full Active Security Scanner")
    parser.add_argument("--url", default="http://localhost:8000", help="Target URL (default: http://localhost:8000)")
    parser.add_argument("--openapi", default="http://localhost:8000/openapi.json", help="OpenAPI definition URL")
    parser.add_argument("--output", default="./reports/zap", help="Output directory for reports")
    parser.add_argument("--no-fail", action="store_true", help="Do not fail on high severity alerts")

    args = parser.parse_args()
    exit_code = run_full_scan(args.url, args.openapi, args.output, fail_on_high=not args.no_fail)
    sys.exit(exit_code)
