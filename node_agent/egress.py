"""Egress allowlist — the "cannot proxy / outbound-only" guarantee.

The node-agent may ONLY make requests to a single allowed base URL: the edge.
Any attempt to reach another host is refused. This is what prevents a malicious
or compromised work unit from turning a volunteer's machine into an open proxy:
there is exactly one reachable destination, and it is fixed at startup.
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
        self.allowed_base_url = f"{parsed.scheme}://{parsed.netloc}"

    def check(self, url: str) -> str:
        """Return `url` if it targets the allowed host; otherwise raise.

        Only the scheme + host[:port] must match. Any path under the allowed
        base is permitted; any other host (or scheme) is refused.
        """
        parsed = urlparse(url)
        if parsed.scheme != self._scheme or parsed.netloc.lower() != self._netloc:
            raise EgressViolation(
                f"egress refused: {url!r} is not under allowlisted "
                f"{self.allowed_base_url!r} (outbound-only guarantee)"
            )
        return url
