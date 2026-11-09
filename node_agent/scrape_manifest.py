"""Signed domain/parser manifest enforcement (plan §6.2).

A node may receive work only for signed manifest entries and fixed audited
extractor IDs; it cannot accept URLs, methods, arbitrary code or proxy
destinations outside the manifest. GET is allowed; a read-only POST only for
an audited immutable GraphQL operation body or persisted-query ID with
explicitly allowed parameters. Mutations and parameter substitutions are
rejected. Private, loopback, link-local, metadata and non-global IPs are
rejected, including IPv4-mapped IPv6.
"""

import ipaddress


class ManifestViolation(Exception):
    pass


def check_destination_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject anything that is not a global unicast address."""
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        raise ManifestViolation(f"non-global IP refused: {addr}")
    if addr.is_reserved or addr.is_unspecified:
        raise ManifestViolation(f"reserved/unspecified IP refused: {addr}")
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) carries the mapped v4 properties
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return check_destination_ip(addr.ipv4_mapped)
    return True


def _entry_for(manifest: dict, host: str, port: int):
    for e in manifest.get("entries", []):
        if e.get("host", "").lower() == host.lower() and int(e.get("port", 443)) == int(port):
            return e
    return None


def request_allowed(manifest: dict, method: str, host: str, port: int, path: str, body: dict | None) -> bool:
    entry = _entry_for(manifest, host, port)
    if entry is None:
        raise ManifestViolation(f"host:port not in signed manifest: {host}:{port}")
    method = method.upper()
    if method == "POST":
        if not entry.get("graphql_persisted"):
            raise ManifestViolation(f"POST not allowed for {host} (no audited GraphQL)")
    elif method not in entry.get("methods", ["GET"]):
        raise ManifestViolation(f"method {method} not allowed for {host}")
    if method == "POST":
        if not body:
            raise ManifestViolation("POST requires an audited body")
        pq = body.get("persistedQuery")
        if not pq:
            raise ManifestViolation("POST only allowed as audited persisted-query GraphQL")
        allowed = entry.get("graphql_persisted", {}).get(pq)
        if allowed is None:
            raise ManifestViolation(f"persisted query {pq} not audited in manifest")
        if body.get("mutation"):
            raise ManifestViolation("mutations rejected")
        variables = body.get("variables", {})
        allowed_params = set(allowed.get("params", []))
        if set(variables.keys()) != allowed_params:
            raise ManifestViolation("parameter substitution rejected")
    return True
