# subdomain.py
# 2026 Joey Manani & Anchorfish Team
# Subdomain extractors

from .base import Feature
from .utils import WWW_LABEL, get_subdomain_labels, shannon_entropy

EMBEDDED_TLDS = frozenset({"com", "net", "org", "edu", "gov"})


def has_www(url: str) -> bool:
    labels = get_subdomain_labels(url)
    return bool(labels) and WWW_LABEL.fullmatch(labels[0]) is not None


def subdomain_labels(url: str) -> tuple:
    """Subdomain labels with a leading www stripped (it has its own feature)."""
    labels = get_subdomain_labels(url)
    return labels[1:] if has_www(url) else labels


class HasWww(Feature):
    name = "has_www"
    description = "Whether the host starts with www (or www1, www2...)."

    def extract(self, url: str) -> bool:
        return has_www(url)


class SubdomainCount(Feature):
    name = "subdomain_count"
    description = "Number of subdomain labels, excluding a leading www."

    def extract(self, url: str) -> int:
        return len(subdomain_labels(url))


class SubdomainLength(Feature):
    name = "subdomain_length"
    description = "Character length of the subdomain, excluding a leading www."

    def extract(self, url: str) -> int:
        return len(".".join(subdomain_labels(url)))


class SubdomainMaxLabelLength(Feature):
    name = "subdomain_max_label_length"
    description = "Length of the longest subdomain label."

    def extract(self, url: str) -> int:
        return max((len(label) for label in subdomain_labels(url)), default=0)


class SubdomainEntropy(Feature):
    name = "subdomain_entropy"
    description = "Shannon entropy of the subdomain, excluding a leading www."

    def extract(self, url: str) -> float:
        return shannon_entropy(".".join(subdomain_labels(url)))


class SubdomainDigitRatio(Feature):
    name = "subdomain_digit_ratio"
    description = "Fraction of subdomain characters that are digits."

    def extract(self, url: str) -> float:
        sub = "".join(subdomain_labels(url))
        return sum(c.isdigit() for c in sub) / len(sub) if sub else 0.0


class SubdomainHyphenCount(Feature):
    name = "subdomain_hyphen_count"
    description = "Number of hyphens in the subdomain."

    def extract(self, url: str) -> int:
        return sum(label.count("-") for label in subdomain_labels(url))


class SubdomainHasPunycode(Feature):
    name = "subdomain_has_punycode"
    description = "Whether any subdomain label is punycode (xn--)."

    def extract(self, url: str) -> bool:
        return any(label.startswith("xn--") for label in subdomain_labels(url))


class SubdomainHasEmbeddedTLD(Feature):
    name = "subdomain_has_embedded_tld"
    description = "Whether the subdomain contains a common TLD label (e.g. paypal.com.evil.net)."

    def extract(self, url: str) -> bool:
        return any(label in EMBEDDED_TLDS for label in subdomain_labels(url))
