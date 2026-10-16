# rootdomain.py
# 2026 Joey Manani & Anchorfish Team
# Root Domain extractor

from .base import Feature
from .utils import get_root_label, shannon_entropy

# get_root_label returns "" for IP hosts and unparseable hosts, so every feature below is safe on bad input

class RootDomain(Feature):

    name = "root_domain"
    description = "The Root Domain of the URL."

    def extract(self, url: str) -> str:
        return get_root_label(url)

class RootDomainLength(Feature):

    name = "root_domain_length"
    description = "The length of the Root Domain"

    def extract(self, url: str) -> int:
        return len(get_root_label(url))

class RootDomainHasHyphen(Feature):

    name = "root_domain_has_hyphen"
    description = "Whether the Root Domain has hyphens."

    def extract(self, url: str) -> bool:
        return "-" in get_root_label(url)

class RootDomainHyphenCount(Feature):

    name = "root_domain_hyphen_count"
    description = "How many hyphens the Root Domain has."

    def extract(self, url: str) -> int:
        return get_root_label(url).count('-')

class RootDomainHasNumber(Feature):

    name = "root_domain_has_number"
    description = "Whether the Root Domain has numbers."

    def extract(self, url: str) -> bool:
        return any(char.isdigit() for char in get_root_label(url))

class RootDomainNumberCount(Feature):

    name = "root_domain_number_count"
    description = "How many numbers the Root Domain has."

    def extract(self, url: str) -> int:
        return sum(char.isdigit() for char in get_root_label(url))

class RootDomainEntropy(Feature):

    name = "root_domain_entropy"
    description = "The Shannon Entropy of the Root Domain."

    def extract(self, url: str) -> float:
        return shannon_entropy(get_root_label(url))

class RootDomainHasPunycode(Feature):
    name = "root_domain_has_punycode"
    description = "Whether the Root Domain label is punycode (xn--)."

    def extract(self, url: str) -> bool:
        return get_root_label(url).startswith("xn--")

class RootDomainDigitRatio(Feature):
    name = "root_domain_digit_ratio"
    description = "Fraction of Root Domain characters that are digits."

    def extract(self, url: str) -> float:
        sub = "".join(get_root_label(url))
        return sum(c.isdigit() for c in sub) / len(sub) if sub else 0.0
