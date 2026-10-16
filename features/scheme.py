# scheme.py
# 2026 Joey Manani & Anchorfish Team
# Scheme extractor

from urllib.parse import urlsplit

from .base import Feature

WEB_SCHEMES = frozenset({"http", "https"})


class Scheme(Feature):
    """Extract the URL scheme (e.g. http, https)."""

    name = "scheme"
    description = "The URL scheme (e.g. http, https)."

    def extract(self, url: str) -> str:
        try:
            return urlsplit(url).scheme.lower()
        except ValueError:
            # e.g. malformed IPv6 like "http://[::1"
            return ""

    @property
    def is_https(self) -> bool:
        """True if the scheme is https."""
        return self.value == "https"

    @property
    def is_obscure(self) -> bool:
        """True if the scheme is anything other than http/https."""
        return self.value not in WEB_SCHEMES