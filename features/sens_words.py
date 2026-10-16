#sens_words.py
# 2026 Joey Manani & Anchorfish Team
# Sensitive words extractor 

from .base import Feature

SENSITIVE_WORDS = frozenset({ #list of common sensitive words from various datasets, see notion 
    "secure",
    "security",
    "account",
    "banking",
    "bank",
    "login",
    "autologin"
    "confirm",
    "sign-in",
    "signin",
    "password",
    "billing",
    "authentication",
    "authenticate",
    "credentials",
    "verification",
    "verify",
    "wallet",
    "update",
    "payment",
})

class NumSensitiveWords(Feature):
    """Counts the number of sensitive words in the URL path and query string."""
    name = "num_sensitive_words"
    description = "Number of common sensitive words found in the URL"

    def extract(self, url:str) -> int:
        url_lower = url.lower()

        count = 0

        for word in SENSITIVE_WORDS:
            if word in url_lower:
                count += 1

        return count

