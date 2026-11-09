"""Red->green for the signed domain/parser manifest rules (plan §6.2).

GET allowed; read-only POST only for an audited immutable GraphQL body or
persisted-query ID with explicitly allowed parameters; mutations and parameter
substitutions rejected; private/loopback/link-local/metadata/non-global IPs
rejected including IPv4-mapped IPv6.
"""

import ipaddress

import pytest


def _mod():
    import importlib

    return importlib.import_module("node_agent.scrape_manifest")


def test_get_allowed_for_manifest_host():
    m = _mod()
    manifest = {"entries": [{"host": "example.com", "port": 443, "methods": ["GET"]}]}
    assert m.request_allowed(manifest, "GET", "example.com", 443, "/x", None)


def test_post_rejected_unless_audited_graphql():
    m = _mod()
    manifest = {"entries": [{"host": "example.com", "port": 443, "methods": ["GET"],
                             "graphql_persisted": {"abc123": {"params": ["id"]}}}]}
    body = {"query": "query", "variables": {"id": "1"}}
    assert m.request_allowed(manifest, "POST", "example.com", 443, "/graphql",
                             {"persistedQuery": "abc123", "variables": {"id": "1"}})
    # mutation rejected
    with pytest.raises(m.ManifestViolation):
        m.request_allowed(manifest, "POST", "example.com", 443, "/graphql",
                          {"persistedQuery": "abc123", "variables": {"id": "1"}, "mutation": True})
    # parameter substitution rejected
    with pytest.raises(m.ManifestViolation):
        m.request_allowed(manifest, "POST", "example.com", 443, "/graphql",
                          {"persistedQuery": "abc123", "variables": {"id": "2", "extra": "x"}})


def test_disallowed_host_rejected():
    m = _mod()
    manifest = {"entries": [{"host": "example.com", "port": 443, "methods": ["GET"]}]}
    with pytest.raises(m.ManifestViolation):
        m.request_allowed(manifest, "GET", "evil.com", 443, "/", None)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                                "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1",
                                "::ffff:169.254.169.254"])
def test_non_global_ip_rejected(ip):
    m = _mod()
    addr = ipaddress.ip_address(ip)
    with pytest.raises(m.ManifestViolation):
        m.check_destination_ip(addr)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_global_ip_allowed(ip):
    m = _mod()
    assert m.check_destination_ip(ipaddress.ip_address(ip))


def test_resolve_and_pin_rejects_rebinding_to_private_ip():
    m = _mod()
    # first resolution global, second (rebinding) private -> must refuse
    calls = {"n": 0}

    def resolver(host, port, proto=0):
        calls["n"] += 1
        ip = "8.8.8.8" if calls["n"] == 1 else "169.254.169.254"
        return [(2, 1, 6, "", (ip, port))]

    assert m.resolve_and_pin("example.com", resolver=resolver) == "8.8.8.8"
    with pytest.raises(m.ManifestViolation):
        m.resolve_and_pin("example.com", resolver=resolver)


def test_redirect_revalidated_against_manifest():
    m = _mod()
    manifest = {"entries": [{"host": "example.com", "port": 443, "methods": ["GET"]}]}
    assert m.revalidate_redirect(manifest, "https://example.com/x", resolver=lambda h, p, proto=0: [(2, 1, 6, "", ("8.8.8.8", p))])
    with pytest.raises(m.ManifestViolation):
        m.revalidate_redirect(manifest, "https://evil.com/x", resolver=lambda h, p, proto=0: [(2, 1, 6, "", ("8.8.8.8", p))])
    with pytest.raises(m.ManifestViolation):
        m.revalidate_redirect(manifest, "file:///etc/passwd")


def test_graphql_inline_query_key_rejected():
    m = _mod()
    manifest = {"entries": [{"host": "example.com", "port": 443, "methods": ["GET"],
                             "graphql_persisted": {"abc123": {"params": ["id"]}}}]}
    with pytest.raises(m.ManifestViolation):
        m.request_allowed(manifest, "POST", "example.com", 443, "/graphql",
                          {"persistedQuery": "abc123", "query": "mutation { x }", "variables": {"id": "1"}})


def test_cookie_lookalike_domain_excluded():
    import importlib
    m = importlib.import_module("node_agent.session_envelope")
    env = m.build_envelope(
        {"cookies": [
            {"name": "s", "domain": ".x.com", "value": "ok"},
            {"name": "evil", "domain": "x.com.evil.tld", "value": "bad"},
            {"name": "sub", "domain": ".sub.x.com", "value": "no"},
        ]},
        target="x.com", account="a", deadline="2026-11-10T00:00:00Z")
    domains = [c["domain"] for c in env["cookies"]]
    assert domains == [".x.com"]
