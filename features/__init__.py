# __init__.py
# 2026 Joey Manani & Anchorfish Team

from .base import Feature
from .path import PathLevel, PathLength, DoubleSlashPath
from .query import QueryLength, NumQueryComponents
from .entropy import Entropy, HostEntropy, PathEntropy, QueryEntropy
from .scheme import Scheme
from .subdomain import HasWww, SubdomainCount, SubdomainLength, SubdomainMaxLabelLength, SubdomainEntropy, SubdomainDigitRatio, SubdomainHyphenCount, SubdomainHasPunycode, SubdomainHasEmbeddedTLD
from .rootdomain import RootDomain, RootDomainLength, RootDomainHasHyphen, RootDomainHyphenCount, RootDomainHasNumber, RootDomainNumberCount, RootDomainEntropy, RootDomainHasPunycode, RootDomainDigitRatio
from .tld import TLD, TLDCount, TLDLength, TLDObscure, TLDCommon
from .utils import normalise_url
from .sens_words import NumSensitiveWords
from .char import QuestionMarkCount, AmpersandCount, DotCount, SlashCount, HyphenCount, UnderscoreCount, UrlLength, DigitRatio, SpecialCharRatio, HashCount, PercentCount, TildeCount, AtCount
from .host import HasAtSymbol, IsIPHost, HasNonStandardPort, HttpsInHostname, DomainHasPunycode, HostLength
from .brand import BrandEditDistance
from .shortener import IsKnownShortener
from .wordstats import LongestWordLength, AvgWordLength
from .file_ext import HasMaliciousFileExtension

FEATURES = [
    PathLevel, PathLength, DoubleSlashPath, QueryLength, NumQueryComponents,
    Entropy, HostEntropy, PathEntropy, QueryEntropy,
    SubdomainCount, SubdomainLength, SubdomainMaxLabelLength, SubdomainEntropy,
    SubdomainDigitRatio, SubdomainHyphenCount, SubdomainHasPunycode, SubdomainHasEmbeddedTLD,
    TLD, TLDCount, TLDLength, TLDObscure, TLDCommon,
    NumSensitiveWords,
    RootDomain, RootDomainLength, RootDomainHasHyphen, RootDomainHyphenCount, RootDomainHasNumber, RootDomainNumberCount, RootDomainEntropy, RootDomainHasPunycode, RootDomainDigitRatio,
    QuestionMarkCount, AmpersandCount, DotCount, SlashCount, HyphenCount, UnderscoreCount, UrlLength, DigitRatio, SpecialCharRatio, HashCount, PercentCount, TildeCount, AtCount,
    HasAtSymbol, IsIPHost, HasNonStandardPort, HttpsInHostname, DomainHasPunycode, HostLength,
    BrandEditDistance,
    IsKnownShortener,
    LongestWordLength, AvgWordLength,
    HasMaliciousFileExtension
]

# scheme and haswww are REMOVED because canonical_url strips the scheme and www (normalising adds http://)
# therefore ALL phishing and legits lack a www and a https scheme and all look the same, so they are now normal

def extract_features(url: str) -> dict:
    """Normalise a URL and run every feature on it."""
    url = normalise_url(url)
    return {f.name: f(url).value for f in FEATURES}

# public api exports
__all__ = ["Feature", "extract_features", *[f.__name__ for f in FEATURES]]
