#!/usr/bin/env python3
"""Fully local, offline demonstration of the whole scan pipeline.

Spins up throwaway local DNS + HTTP responders (127.0.0.1 only — no real
internet access, no third-party domain touched) and runs check_subdomain()
against four synthetic scenarios: a truly dangling CNAME, a claimed resource
that still matches a service's "unclaimed" fingerprint, a properly claimed
resource, and a subdomain with no CNAME at all. Writes sample_report.md from
these real (if local) socket round-trips.

Why local and not a live domain: this tool's job is subdomain *enumeration*
against a specific target, which — unlike a plain SPF/DMARC DNS lookup — is
a recon technique that shouldn't be run against a third party without
authorization. There's no equivalent of Port-Scan-Reporter's scanme.nmap.org
(a domain explicitly offered up for this kind of testing), so the canonical
example here is a self-contained local fixture instead.
"""

import http.server
import socket
import struct
import threading

from subdomain_takeover_scanner import (
    TYPE_A,
    TYPE_CNAME,
    build_report,
    check_subdomain,
    encode_qname,
)


def build_dns_message(query_id: int, question: bytes, rcode: int, records: list) -> bytes:
    flags = 0x8180 | (rcode & 0x000F)
    header = struct.pack(">HHHHHH", query_id, flags, 1, len(records), 0, 0)
    answers = b""
    for rtype, rdata in records:
        answers += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + answers


class FakeDnsServer:
    """responses: {qtype: (rcode, [(rtype, rdata), ...])}"""

    def __init__(self, responses: dict):
        self.responses = responses
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        # Short recv timeout so the loop wakes up regularly to check _stop,
        # instead of blocking indefinitely — closing the socket out from under
        # a still-blocked recvfrom() raises on Windows, so close() joins the
        # thread (letting it exit on its own via this timeout) before closing.
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:
                return
            query_id = struct.unpack(">H", data[:2])[0]
            qtype = struct.unpack(">H", data[-4:-2])[0]
            question = data[12:]
            rcode, records = self.responses.get(qtype, (3, []))
            self.sock.sendto(build_dns_message(query_id, question, rcode, records), addr)

    def close(self):
        self._stop = True
        self.thread.join(timeout=2.0)
        self.sock.close()


class FakeHttpServer:
    def __init__(self, body: str, status: int = 200):
        encoded_body = body.encode("utf-8")

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(encoded_body)

            def log_message(self, fmt, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=2.0)
        self.server.server_close()


def scenario_dangling_cname():
    dns = FakeDnsServer({
        TYPE_CNAME: (0, [(TYPE_CNAME, encode_qname("old-project.github.io"))]),
        TYPE_A: (3, []),
    })
    try:
        return check_subdomain("blog.demo.test", resolver="127.0.0.1", port=dns.port, timeout=2.0)
    finally:
        dns.close()


def scenario_fingerprint_match():
    dns = FakeDnsServer({
        TYPE_CNAME: (0, [(TYPE_CNAME, encode_qname("tenant.myshopify.com"))]),
        TYPE_A: (0, [(TYPE_A, bytes([93, 184, 216, 34]))]),
    })
    http_server = FakeHttpServer("Sorry, this shop is currently unavailable.", status=404)
    try:
        return check_subdomain(
            "shop.demo.test", resolver="127.0.0.1", port=dns.port, timeout=2.0,
            http_base_url=f"http://127.0.0.1:{http_server.port}/",
        )
    finally:
        http_server.close()
        dns.close()


def scenario_properly_claimed():
    dns = FakeDnsServer({
        TYPE_CNAME: (0, [(TYPE_CNAME, encode_qname("prod.myshopify.com"))]),
        TYPE_A: (0, [(TYPE_A, bytes([93, 184, 216, 35]))]),
    })
    http_server = FakeHttpServer("<html>Welcome to our real storefront.</html>", status=200)
    try:
        return check_subdomain(
            "www.demo.test", resolver="127.0.0.1", port=dns.port, timeout=2.0,
            http_base_url=f"http://127.0.0.1:{http_server.port}/",
        )
    finally:
        http_server.close()
        dns.close()


def scenario_no_cname():
    dns = FakeDnsServer({TYPE_CNAME: (3, [])})
    try:
        return check_subdomain("mail.demo.test", resolver="127.0.0.1", port=dns.port, timeout=2.0)
    finally:
        dns.close()


def main():
    results = [
        scenario_dangling_cname(),
        scenario_fingerprint_match(),
        scenario_properly_claimed(),
        scenario_no_cname(),
    ]
    findings = [r for r in results if r is not None]
    result = {"domain": "demo.test", "checked": len(results), "findings": findings}

    report = build_report(result)
    with open("sample_report.md", "w", encoding="utf-8") as fh:
        fh.write(report)
    print(report)
    print(f"({len(findings)} of {len(results)} synthetic subdomains flagged)")


if __name__ == "__main__":
    main()
