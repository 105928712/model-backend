# brand.py
# 2026 Joey Manani & Anchorfish Team
# Brand impersonation extractor

from Levenshtein import distance as levenshtein

from .base import Feature
from .utils import get_root_label

COMMON_BRANDS = frozenset({
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "instagram", "netflix", "bankofamerica", "wellsfargo", "chase",
    "dhl", "fedex", "ebay", "linkedin", "whatsapp", "outlook",
    "office365", "adobe", "americanexpress", "hsbc", "icloud", "usps",
})


class BrandEditDistance(Feature):
    """How close the root domain is to a known brand name - low distance + wrong domain = typosquatting."""
    name = "brand_edit_distance"
    description = "Smallest edit distance between the root domain and a list of commonly impersonated brand names."

    def extract(self, url: str) -> int:
        root = get_root_label(url)
        return min(levenshtein(root, brand) for brand in COMMON_BRANDS)
