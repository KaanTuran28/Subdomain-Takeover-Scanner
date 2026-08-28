#!/usr/bin/env python3
"""Scans a domain's subdomains for dangling-CNAME takeover risk.

For each candidate subdomain, resolves its CNAME (a small, from-scratch
UDP DNS client — no `dnspython`, same approach as this portfolio's
`DNS-Security-Auditor`), checks whether the CNAME target matches a known
cloud-service pattern, and — if so — whether the target still resolves and
whether the site returns that service's published "unclaimed resource"
fingerprint (the same public fingerprint database bug-bounty tooling like
`can-i-take-over-xyz` documents).

Authorized use only: only run this against a domain you own or are
explicitly authorized to test. See `demo_local.py` for a fully offline,
zero-external-target demonstration of the whole pipeline.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path

TYPE_A = 1
TYPE_CNAME = 5
CLASS_IN = 1

DEFAULT_WORDLIST = [
    "www", "blog", "dev", "staging", "api", "shop", "cdn", "assets",
    "docs", "help", "status", "mail", "app", "portal", "admin", "test",
]

VULNERABLE_SERVICES = [
    {"name": "GitHub Pages", "cname_patterns": ("github.io",), "fingerprint": "There isn't a GitHub Pages site here."},
    {"name": "Heroku", "cname_patterns": ("herokuapp.com", "herokudns.com"), "fingerprint": "No such app"},
    {"name": "AWS S3", "cname_patterns": ("s3.amazonaws.com", "s3-website"), "fingerprint": "NoSuchBucket"},
    {"name": "Shopify", "cname_patterns": ("myshopify.com",), "fingerprint": "Sorry, this shop is currently unavailable."},
    {"name": "Fastly", "cname_patterns": ("fastly.net",), "fingerprint": "Fastly error: unknown domain"},
    {"name": "Surge.sh", "cname_patterns": ("surge.sh",), "fingerprint": "project not found"},
    {"name": "Unbounce", "cname_patterns": ("unbouncepages.com",), "fingerprint": "The requested URL was not found on this server."},
    {"name": "Tumblr", "cname_patterns": ("tumblr.com",), "fingerprint": "Whatever you were looking for doesn't currently exist"},
]


class DnsQueryError(Exception):
    pass


def encode_qname(domain: str) -> bytes:
    labels = [label for label in domain.rstrip(".").split(".") if label]
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels)
    return encoded + b"\x00"


def build_query(domain: str, qtype: int) -> tuple:
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = encode_qname(domain) + struct.pack(">HH", qtype, CLASS_IN)
    return header + question, query_id


def decode_name(data: bytes, offset: int) -> tuple:
    labels = []
    jumped_from = None
    steps = 0
    while True:
        steps += 1
        if steps > 128:
            raise DnsQueryError("DNS name decompression loop (malformed response)")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if jumped_from is None:
                jumped_from = offset + 2
            offset = pointer
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), (jumped_from if jumped_from is not None else offset)


def parse_response(data: bytes, expected_id: int, qtype: int) -> list:
    if len(data) < 12:
        raise DnsQueryError("response shorter than a DNS header")
    query_id, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if query_id != expected_id:
        raise DnsQueryError("DNS response ID mismatch")
    if flags & 0x000F != 0:
        return []
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(data, offset)
        offset += 4
    records = []
    for _ in range(ancount):
        _, offset = decode_name(data, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == qtype:
            if qtype == TYPE_CNAME:
                name, _ = decode_name(data, offset - rdlength)
                records.append(name)
            else:
                records.append(rdata)
    return records


def query(domain: str, qtype: int, resolver: str = "8.8.8.8", port: int = 53, timeout: float = 5.0) -> list:
    packet, query_id = build_query(domain, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (resolver, port))
        data, _ = sock.recvfrom(65535)
    return parse_response(data, query_id, qtype)


def resolves(domain: str, resolver: str = "8.8.8.8", port: int = 53, timeout: float = 5.0) -> bool:
    try:
        return bool(query(domain, TYPE_A, resolver=resolver, port=port, timeout=timeout))
    except (DnsQueryError, OSError):
        return False


def match_vulnerable_service(cname_target: str):
    target = cname_target.lower().rstrip(".")
    for service in VULNERABLE_SERVICES:
        if any(pattern in target for pattern in service["cname_patterns"]):
            return service
    return None


def fetch_body(url: str, timeout: float = 5.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read(20000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.read(20000).decode("utf-8", errors="replace")
        except OSError:
            return None
    except (urllib.error.URLError, OSError):
        return None


def finding(severity: str, check: str, subdomain: str, reason: str, recommendation: str) -> dict:
    return {"severity": severity, "check": check, "subdomain": subdomain, "reason": reason, "recommendation": recommendation}


def check_subdomain(
    fqdn: str, resolver: str = "8.8.8.8", port: int = 53, timeout: float = 5.0, http_base_url: str | None = None
):
    try:
        cname_records = query(fqdn, TYPE_CNAME, resolver=resolver, port=port, timeout=timeout)
    except (DnsQueryError, OSError):
        return None
    if not cname_records:
        return None

    cname_target = cname_records[0]
    service = match_vulnerable_service(cname_target)
    if service is None:
        return None

    if not resolves(cname_target, resolver=resolver, port=port, timeout=timeout):
        return finding(
            "HIGH", "dangling_cname", fqdn,
            f'CNAME points to "{cname_target}" ({service["name"]}), which does not resolve at all — '
            "a classic dangling-CNAME takeover setup.",
            "Remove the CNAME record, or reclaim/reconfigure the target resource before an attacker does.",
        )

    url = http_base_url if http_base_url is not None else f"http://{fqdn}/"
    body = fetch_body(url, timeout=timeout)
    if body is None:
        return finding(
            "MEDIUM", "unverified_third_party_cname", fqdn,
            f'CNAME points to a known third-party service ({service["name"]}: "{cname_target}") but the '
            "site could not be reached over HTTP to verify claim status.",
            "Manually verify whether this resource is still claimed/owned by your organization.",
        )
    if service["fingerprint"] in body:
        return finding(
            "HIGH", "subdomain_takeover_fingerprint", fqdn,
            f'CNAME points to {service["name"]} ("{cname_target}") and the site returns its published '
            f'"unclaimed resource" fingerprint ("{service["fingerprint"]}").',
            f"Claim the {service['name']} resource under your account, or remove the CNAME record if it's no longer needed.",
        )
    return None


def scan_domain(domain: str, wordlist: list, resolver: str = "8.8.8.8", port: int = 53, timeout: float = 5.0) -> dict:
    findings = []
    for prefix in wordlist:
        fqdn = f"{prefix}.{domain}"
        result = check_subdomain(fqdn, resolver=resolver, port=port, timeout=timeout)
        if result is not None:
            findings.append(result)
    return {"domain": domain, "checked": len(wordlist), "findings": findings}


def build_report(result: dict) -> str:
    findings = result["findings"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    lines = [
        f"# Subdomain Takeover Scan — {result['domain']}",
        "",
        f"- **Subdomains checked:** {result['checked']}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM",
        "",
    ]
    if findings:
        lines += ["| Severity | Subdomain | Check | Reason |", "|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1}
        for f in sorted(findings, key=lambda f: order[f["severity"]]):
            reason = f["reason"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['subdomain']} | {f['check']} | {reason} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(result: dict) -> str:
    findings = result["findings"]
    payload = {
        **result,
        "summary": {
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        },
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Scan a domain's subdomains for dangling-CNAME takeover risk. "
                    "Authorized use only — only scan a domain you own or are explicitly permitted to test."
    )
    parser.add_argument("--domain", required=True, help="Domain to scan, e.g. example.com")
    parser.add_argument("--wordlist", help="Path to a file of subdomain prefixes, one per line (default: built-in list).")
    parser.add_argument("--resolver", default="8.8.8.8", help="DNS resolver IP to query (default: 8.8.8.8)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-query timeout in seconds")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    if args.wordlist:
        wordlist = [line.strip() for line in Path(args.wordlist).read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        wordlist = DEFAULT_WORDLIST

    result = scan_domain(args.domain, wordlist, resolver=args.resolver, timeout=args.timeout)
    report = build_json_report(result) if args.format == "json" else build_report(result)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    high_count = sum(1 for f in result["findings"] if f["severity"] == "HIGH")
    medium_count = sum(1 for f in result["findings"] if f["severity"] == "MEDIUM")
    print(f"Checked {result['checked']} subdomain(s) of {args.domain}: {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
