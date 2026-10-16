# tld.py
# 2026 Joey Manani & Anchorfish Team
# TLD extractor

from .base import Feature
from .utils import get_tld

COMMON_ABUSED_TLDS = frozenset({"xyz", "top", "xin", "bond", "buzz", "sbs", "cfd", "lol", "ru", "cc", "shop", "online", "cn", "monster", "world", "win", "support", "vip", "icu", "pro", "me", "gz", "ml", "tk"})

COMMON_TLDS = frozenset({"com", "net", "org", "co"})

# get_tld returns "" for IP hosts and unparseable hosts, so every feature below is safe on bad input

class TLD(Feature):

    name = "tld"
    description = "The top-level domain (TLD) of the URL."

    def extract(self, url: str) -> str:
        return get_tld(url)

class TLDCount(Feature):

    name = "tld_count"
    description = "The number of top-level domains (TLDs) within the URL."

    def extract(self, url:str) -> int:
        tld = get_tld(url)
        return len(tld.split('.')) if tld else 0

class TLDLength(Feature):

    name = "tld_length"
    description = "Character length of the top-level domain (TLD)."

    def extract(self, url:str) -> int:
        return len(get_tld(url))

class TLDObscure(Feature):

    name = "tld_is_commonly_abused"
    description = "If the top-level domain (TLD) is one that is commonly abused"

    def extract(self, url:str) -> bool:
        return get_tld(url) in COMMON_ABUSED_TLDS

class TLDCommon(Feature):

    name = "tld_is_common"
    description = "If the top-level domain (TLD) is common"

    def extract(self, url:str) -> bool:
        return get_tld(url) in COMMON_TLDS
