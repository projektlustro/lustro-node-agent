"""Egress allowlist — the "cannot proxy / outbound-only" guarantee.

The node-agent may ONLY make requests to a single allowed base URL: the edge.
Any attempt to reach another host is refused. This is what prevents a malicious
or compromised work unit from turning a volunteer's machine into an open proxy:
there is exactly one reachable destination, and it is fixed at startup.

Security: This module handles URL parsing edge cases to prevent egress bypass
attacks via malformed URLs (e.g., URLs with @ in netloc, port confusion, etc.)
"""

from urllib.parse import urlparse


class EgressViolation(Exception):
    """Raised when a request targets a host outside the allowlist."""


class EgressGuard:
    def __init__(self, allowed_base_url: str) -> None:
        parsed = urlparse(allowed_base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid allowed_base_url: {allowed_base_url!r}")
        self._scheme = parsed.scheme
        self._netloc = parsed.netloc.lower()
        # Extract the hostname from netloc (handles userinfo with @)
        self._hostname = parsed.hostname or parsed.netloc.split("@")[-1].split(":")[0].lower()
        # Extract port
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.allowed_base_url = f"{parsed.scheme}://{parsed.netloc}"

    def check(self, url: str) -> str:
        """Return `url` if it targets the allowed host; otherwise raise.

        Only the scheme + host[:port] must match. Any path under the allowed
        base is permitted; any other host (or scheme) is refused.
        
        Security: Handles URL parsing edge cases including:
        - userinfo in netloc (user:pass@host)
        - port specifications
        - scheme mismatches
        - @ character in hostnames
        """
        parsed = urlparse(url)
        
        # Validate scheme
        if parsed.scheme != self._scheme:
            raise EgressViolation(
                f"egress refused: {url!r} scheme {parsed.scheme!r} != allowlisted "
                f"{self._scheme!r} (outbound-only guarantee)"
            )
        
        # Extract actual hostname (handles userinfo with @)
        hostname = parsed.hostname
        if not hostname:
            # Fallback for URLs without standard parsing
            netloc = parsed.netloc
            hostname = netloc.split("@")[-1].split(":")[0].lower()
        else:
            hostname = hostname.lower()
        
        # Validate hostname
        if hostname != self._hostname:
            raise EgressViolation(
                f"egress refused: {url!r} host {hostname!r} is not under allowlisted "
                f"{self.allowed_base_url!r} (outbound-only guarantee)"
            )
        
        # Validate port (if specified)
        if parsed.port and parsed.port != self._port:
            # If the URL specifies a port, it must match our expected port
            raise EgressViolation(
                f"egress refused: {url!r} port {parsed.port} != allowlisted port "
                f"{self._port} (outbound-only guarantee)"
            )
        
        return url
