import json
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import subdomain_takeover_scanner as sts
from subdomain_takeover_scanner import (
    DnsQueryError,
    build_json_report,
    build_report,
    check_subdomain,
    encode_qname,
    fetch_body,
    main,
    match_vulnerable_service,
    parse_response,
    query,
    scan_domain,
)

# ---------------------------------------------------------------------------
# Wire format (pure, no network)
# ---------------------------------------------------------------------------

def build_fake_dns_message(query_id, question, rcode, records):
    """records: list of (rtype, rdata_bytes)"""
    flags = 0x8180 | (rcode & 0x000F)
    header = struct.pack(">HHHHHH", query_id, flags, 1, len(records), 0, 0)
    answers = b""
    for rtype, rdata in records:
        answers += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + answers


def test_parse_response_rejects_mismatched_id():
    question = encode_qname("x.example.com") + struct.pack(">HH", sts.TYPE_CNAME, 1)
    msg = build_fake_dns_message(1, question, 0, [])
    with pytest.raises(DnsQueryError):
        parse_response(msg, expected_id=2, qtype=sts.TYPE_CNAME)


def test_parse_response_returns_empty_for_error_rcode():
    question = encode_qname("x.example.com") + struct.pack(">HH", sts.TYPE_CNAME, 1)
    msg = build_fake_dns_message(42, question, rcode=3, records=[])
    assert parse_response(msg, expected_id=42, qtype=sts.TYPE_CNAME) == []


def test_parse_response_decodes_cname_target():
    question = encode_qname("blog.example.com") + struct.pack(">HH", sts.TYPE_CNAME, 1)
    cname_rdata = encode_qname("tenant.github.io")
    msg = build_fake_dns_message(7, question, 0, [(sts.TYPE_CNAME, cname_rdata)])
    records = parse_response(msg, expected_id=7, qtype=sts.TYPE_CNAME)
    assert records == ["tenant.github.io"]


class FakeDnsServer:
    def __init__(self, responder):
        self.responder = responder
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(2.0)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            data, addr = self.sock.recvfrom(512)
        except TimeoutError:
            return
        query_id = struct.unpack(">H", data[:2])[0]
        question = data[12:]
        response = self.responder(query_id, question)
        self.sock.sendto(response, addr)

    def close(self):
        self.thread.join(timeout=2.0)
        self.sock.close()


def test_query_cname_over_real_udp_socket():
    def responder(query_id, question):
        return build_fake_dns_message(query_id, question, 0, [(sts.TYPE_CNAME, encode_qname("tenant.github.io"))])

    server = FakeDnsServer(responder)
    try:
        records = query("blog.example.com", sts.TYPE_CNAME, resolver="127.0.0.1", port=server.port, timeout=1.0)
        assert records == ["tenant.github.io"]
    finally:
        server.close()


def test_resolves_returns_false_on_nxdomain():
    def responder(query_id, question):
        return build_fake_dns_message(query_id, question, rcode=3, records=[])

    server = FakeDnsServer(responder)
    try:
        assert sts.resolves("nowhere.github.io", resolver="127.0.0.1", port=server.port, timeout=1.0) is False
    finally:
        server.close()


def test_resolves_returns_true_when_a_record_present():
    def responder(query_id, question):
        return build_fake_dns_message(query_id, question, 0, [(sts.TYPE_A, bytes([185, 199, 108, 153]))])

    server = FakeDnsServer(responder)
    try:
        assert sts.resolves("pages.github.io", resolver="127.0.0.1", port=server.port, timeout=1.0) is True
    finally:
        server.close()


# ---------------------------------------------------------------------------
# Fingerprint matching (pure)
# ---------------------------------------------------------------------------

def test_match_vulnerable_service_github_pages():
    service = match_vulnerable_service("some-tenant.github.io")
    assert service is not None and service["name"] == "GitHub Pages"


def test_match_vulnerable_service_heroku():
    service = match_vulnerable_service("my-app.herokuapp.com")
    assert service["name"] == "Heroku"


def test_match_vulnerable_service_no_match_for_normal_host():
    assert match_vulnerable_service("mail.google.com") is None


# ---------------------------------------------------------------------------
# check_subdomain orchestration (DNS mocked via a local fake server; HTTP via
# a monkeypatched fetch_body — no real internet access)
# ---------------------------------------------------------------------------

def test_check_subdomain_no_cname_returns_none(monkeypatch):
    monkeypatch.setattr(sts, "query", lambda *a, **k: [])
    assert check_subdomain("www.example.com") is None


def test_check_subdomain_cname_to_unknown_service_returns_none(monkeypatch):
    monkeypatch.setattr(sts, "query", lambda domain, qtype, **k: ["mail.google.com"] if qtype == sts.TYPE_CNAME else [])
    assert check_subdomain("mail.example.com") is None


def test_check_subdomain_dangling_cname_flagged_high(monkeypatch):
    def fake_query(domain, qtype, **k):
        return ["abandoned.github.io"] if qtype == sts.TYPE_CNAME else []

    monkeypatch.setattr(sts, "query", fake_query)
    result = check_subdomain("blog.example.com")
    assert result["severity"] == "HIGH"
    assert result["check"] == "dangling_cname"


def test_check_subdomain_fingerprint_match_flagged_high(monkeypatch):
    def fake_query(domain, qtype, **k):
        if qtype == sts.TYPE_CNAME:
            return ["tenant.github.io"]
        return [b"\x01\x02\x03\x04"]  # target resolves fine

    monkeypatch.setattr(sts, "query", fake_query)
    monkeypatch.setattr(sts, "fetch_body", lambda url, timeout=5.0: "There isn't a GitHub Pages site here.")
    result = check_subdomain("blog.example.com")
    assert result["severity"] == "HIGH"
    assert result["check"] == "subdomain_takeover_fingerprint"


def test_check_subdomain_claimed_resource_not_flagged(monkeypatch):
    def fake_query(domain, qtype, **k):
        if qtype == sts.TYPE_CNAME:
            return ["tenant.github.io"]
        return [b"\x01\x02\x03\x04"]

    monkeypatch.setattr(sts, "query", fake_query)
    monkeypatch.setattr(sts, "fetch_body", lambda url, timeout=5.0: "<html>My real blog</html>")
    assert check_subdomain("blog.example.com") is None


def test_check_subdomain_unreachable_http_flagged_medium(monkeypatch):
    def fake_query(domain, qtype, **k):
        if qtype == sts.TYPE_CNAME:
            return ["tenant.github.io"]
        return [b"\x01\x02\x03\x04"]

    monkeypatch.setattr(sts, "query", fake_query)
    monkeypatch.setattr(sts, "fetch_body", lambda url, timeout=5.0: None)
    result = check_subdomain("blog.example.com")
    assert result["severity"] == "MEDIUM"
    assert result["check"] == "unverified_third_party_cname"


def test_check_subdomain_dns_error_returns_none(monkeypatch):
    def raise_error(*a, **k):
        raise OSError("network unreachable")

    monkeypatch.setattr(sts, "query", raise_error)
    assert check_subdomain("blog.example.com") is None


def test_fetch_body_returns_none_on_url_error(monkeypatch):
    import urllib.error

    def raise_url_error(*a, **k):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(sts.urllib.request, "urlopen", raise_url_error)
    assert fetch_body("http://nowhere.invalid/") is None


# ---------------------------------------------------------------------------
# scan_domain / reports / main
# ---------------------------------------------------------------------------

def test_scan_domain_aggregates_findings_across_wordlist(monkeypatch):
    def fake_check(fqdn, **kwargs):
        if fqdn.startswith("blog."):
            return {"severity": "HIGH", "check": "dangling_cname", "subdomain": fqdn, "reason": "r", "recommendation": "x"}
        return None

    monkeypatch.setattr(sts, "check_subdomain", fake_check)
    result = scan_domain("example.com", ["www", "blog", "api"])
    assert result["checked"] == 3
    assert len(result["findings"]) == 1
    assert result["findings"][0]["subdomain"] == "blog.example.com"


def test_build_report_lists_findings():
    result = {"domain": "example.com", "checked": 5, "findings": [
        {"severity": "HIGH", "check": "dangling_cname", "subdomain": "blog.example.com", "reason": "r", "recommendation": "x"},
    ]}
    report = build_report(result)
    assert "HIGH" in report
    assert "blog.example.com" in report


def test_build_report_clean_says_no_issues():
    report = build_report({"domain": "example.com", "checked": 5, "findings": []})
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_summary():
    result = {"domain": "example.com", "checked": 5, "findings": [
        {"severity": "HIGH", "check": "dangling_cname", "subdomain": "blog.example.com", "reason": "r", "recommendation": "x"},
        {"severity": "MEDIUM", "check": "unverified_third_party_cname", "subdomain": "api.example.com", "reason": "r", "recommendation": "x"},
    ]}
    payload = json.loads(build_json_report(result))
    assert payload["summary"] == {"high": 1, "medium": 1}


def run_main(monkeypatch, tmp_path, scan_result, extra_args):
    monkeypatch.setattr(sts, "scan_domain", lambda *a, **k: scan_result)
    out = str(tmp_path / "out.md")
    argv = ["subdomain_takeover_scanner.py", "--domain", "example.com", "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_when_high_finding_present(monkeypatch, tmp_path):
    result = {"domain": "example.com", "checked": 16, "findings": [
        {"severity": "HIGH", "check": "dangling_cname", "subdomain": "blog.example.com", "reason": "r", "recommendation": "x"},
    ]}
    assert run_main(monkeypatch, tmp_path, result, ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_clean_result(monkeypatch, tmp_path):
    result = {"domain": "example.com", "checked": 16, "findings": []}
    assert run_main(monkeypatch, tmp_path, result, ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    result = {"domain": "example.com", "checked": 16, "findings": [
        {"severity": "HIGH", "check": "dangling_cname", "subdomain": "blog.example.com", "reason": "r", "recommendation": "x"},
    ]}
    assert run_main(monkeypatch, tmp_path, result, []) == 0


def test_main_uses_custom_wordlist_file(monkeypatch, tmp_path):
    wordlist_path = tmp_path / "words.txt"
    wordlist_path.write_text("alpha\nbeta\n\ngamma\n", encoding="utf-8")

    captured = {}

    def fake_scan_domain(domain, wordlist, **kwargs):
        captured["wordlist"] = wordlist
        return {"domain": domain, "checked": len(wordlist), "findings": []}

    monkeypatch.setattr(sts, "scan_domain", fake_scan_domain)
    out = str(tmp_path / "out.md")
    argv = ["subdomain_takeover_scanner.py", "--domain", "example.com", "--wordlist", str(wordlist_path), "--output", out]
    monkeypatch.setattr(sys, "argv", argv)
    main()
    assert captured["wordlist"] == ["alpha", "beta", "gamma"]
