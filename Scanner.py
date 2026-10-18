#!/usr/bin/env python3
"""Nmap scan automation: runs a service scan, parses the XML
output, flags risky open ports, and saves a text report."""

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

RISKY_PORTS = {
    21: "FTP (cleartext credentials)",
    23: "Telnet (cleartext remote access)",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB (common attack target)",
    3389: "RDP (brute-force target)",
}


def run_scan(target, ports):
    cmd = ["nmap", "-sV", "-p", ports, "-oX", "-", target]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600
        )
    except FileNotFoundError:
        sys.exit("nmap not found. Install it: sudo apt install nmap")
    except subprocess.TimeoutExpired:
        sys.exit("Scan timed out.")
    if result.returncode != 0:
        sys.exit(f"nmap error: {result.stderr.strip()}")
    return result.stdout


def parse_results(xml_text):
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = host.find("address").get("addr")
        open_ports = []
        for p in host.findall("./ports/port"):
            if p.find("state").get("state") != "open":
                continue
            svc = p.find("service")
            open_ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": svc.get("name", "unknown") if svc is not None else "unknown",
                "version": (
                    f"{svc.get('product', '')} {svc.get('version', '')}".strip()
                    if svc is not None else ""
                ),
            })
        hosts.append({"ip": addr, "ports": open_ports})
    return hosts


def build_report(target, hosts):
    lines = [
        "NMAP SCAN REPORT",
        f"Target : {target}",
        f"Time   : {datetime.now():%Y-%m-%d %H:%M:%S}",
        "=" * 60,
    ]
    if not hosts:
        lines.append("No live hosts found.")
    for h in hosts:
        lines.append(f"\nHost: {h['ip']}")
        if not h["ports"]:
            lines.append("  No open ports found.")
        for p in h["ports"]:
            line = f"  {p['port']}/{p['proto']:<4} {p['service']:<12} {p['version']}"
            if p["port"] in RISKY_PORTS:
                line += f"  [RISK: {RISKY_PORTS[p['port']]}]"
            lines.append(line)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Nmap scan automator")
    parser.add_argument("target", help="IP, hostname, or CIDR range")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="port range (default: 1-1024)")
    parser.add_argument("-o", "--output", help="report file name")
    args = parser.parse_args()

    print(f"[*] Scanning {args.target} ports {args.ports} ...")
    hosts = parse_results(run_scan(args.target, args.ports))
    report = build_report(args.target, hosts)
    print(report)

    out = args.output or f"scan_report_{datetime.now():%Y%m%d_%H%M%S}.txt"
    with open(out, "w") as f:
        f.write(report + "\n")
    print(f"\n[+] Report saved to {out}")


if __name__ == "__main__":
    main()
