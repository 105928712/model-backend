# char.py
# 2026 Joey Manani & Anchorfish Team
# Character feature extractor

from .base import Feature

class CharCountFeature(Feature):
    """Base for features that count occurrences of a single character."""

    char: str  # set by subclass

    def extract(self, url: str) -> int:
        return url.count(self.char)

class QuestionMarkCount(CharCountFeature):
    """Extract the number of question marks in the URL."""
    name = "question_mark_count"
    description = "The number of question marks in the URL."
    char = "?"

class AmpersandCount(CharCountFeature):
    """Extract the number of ampersands in the URL."""
    name = "ampersand_count"
    description = "The number of ampersands in the URL."
    char = "&"

class DotCount(CharCountFeature):
    """Extract the number of dots in the URL."""
    name = "dot_count"
    description = "The number of dots in the URL."
    char = "."

class SlashCount(CharCountFeature):
    """Extract the number of slashes in the URL."""
    name = "slash_count"
    description = "The number of slashes in the URL."
    char = "/"

class HyphenCount(CharCountFeature):
    """Extract the number of hyphens in the URL."""
    name = "hyphen_count"
    description = "The number of hyphens in the URL."
    char = "-"

class UnderscoreCount(CharCountFeature):
    """Extract the number of underscores in the URL."""
    name = "underscore_count"
    description = "The number of underscores in the URL."
    char = "_"

class HashCount(CharCountFeature):
    """Extract the number of hashes in the URL."""
    name = "hash_count"
    description = "The number of hashes in the URL."
    char = "#"

class PercentCount(CharCountFeature):
    """Extract the number of percent signs in the URL."""
    name = "percent_count"
    description = "The number of percent signs in the URL."
    char = "%"

class TildeCount(CharCountFeature):
    """Extract the number of tildes in the URL."""
    name = "tilde_count"
    description = "The number of tildes in the URL."
    char = "~"

class AtCount(CharCountFeature):
    """Extract the number of at symbols in the URL."""
    name = "at_count"
    description = "The number of at symbols in the URL."
    char = "@"

class UrlLength(Feature):
    name = "url_length"
    description = "Total character length of the URL."

    def extract(self, url: str) -> int:
        return len(url)

class DigitRatio(Feature):
    name = "digit_ratio"
    description = "Fraction of the URL that's digits."

    def extract(self, url: str) -> float:
        return sum(c.isdigit() for c in url) / len(url) if url else 0.0

class SpecialCharRatio(Feature):
    name = "special_char_ratio"
    description = "Fraction of the URL that's non-alphanumeric characters."

    def extract(self, url: str) -> float:
        return sum(not c.isalnum() for c in url) / len(url) if url else 0.0
