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
