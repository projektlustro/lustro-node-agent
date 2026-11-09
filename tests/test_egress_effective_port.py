"""Red->green for the egress effective-port fix (plan §4.5).

Bug: a request URL that omits the port was accepted even when the configured
edge uses a different EXPLICIT port, because the check only fired when the
request URL carried a port. The effective port (default for the scheme) must
always be compared.
"""

import pytest

from node_agent.egress import EgressGuard, EgressViolation


def test_omitted_port_must_match_effective_port_of_explicit_edge_port():
    # edge configured with explicit port 8443; request omits port -> effective 443 -> refuse
    guard = EgressGuard("https://edge.example:8443")
    with pytest.raises(EgressViolation):
        guard.check("https://edge.example/v1/wu")


def test_omitted_port_allowed_when_edge_uses_default_port():
    guard = EgressGuard("https://edge.example")
    assert guard.check("https://edge.example/v1/wu") == "https://edge.example/v1/wu"


def test_explicit_matching_port_allowed():
    guard = EgressGuard("https://edge.example:8443")
    assert guard.check("https://edge.example:8443/v1/wu")


def test_explicit_mismatched_port_refused():
    guard = EgressGuard("https://edge.example:8443")
    with pytest.raises(EgressViolation):
        guard.check("https://edge.example:9443/v1/wu")


def test_http_default_port_80():
    guard = EgressGuard("http://edge.example:8080")
    with pytest.raises(EgressViolation):
        guard.check("http://edge.example/v1/wu")  # effective 80 != 8080
    assert guard.check("http://edge.example:8080/v1/wu")


def test_other_host_still_refused():
    guard = EgressGuard("https://edge.example:8443")
    with pytest.raises(EgressViolation):
        guard.check("https://evil.example:8443/v1/wu")
