# shortener.py
# 2026 Joey Manani & Anchorfish Team
# URL shortener extractor

from .base import Feature
from .utils import get_host, psl

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "tiny.cc", "rebrand.ly", "cutt.ly", "adf.ly",
    "rb.gy", "v.gd", "shorte.st", "s.id", "bl.ink",
})


class IsKnownShortener(Feature):
    """Shorteners hide the real destination of a phishing link."""
    name = "is_known_shortener"
    description = "Whether the URL's domain is a known link-shortening service."

    def extract(self, url: str) -> bool:
        host = get_host(url)
        registrable = psl.privatesuffix(host) if host else ""
        return registrable in KNOWN_SHORTENERS
