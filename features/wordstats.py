# wordstats.py
# 2026 Joey Manani & Anchorfish Team
# Word token extractors

import re

from .base import Feature

_WORD_SPLIT = re.compile(r"[^a-zA-Z0-9]+")


def _words(url: str) -> list:
    return [w for w in _WORD_SPLIT.split(url) if w]


class LongestWordLength(Feature):
    name = "longest_word_length"
    description = "Length of the longest alphanumeric token in the URL."

    def extract(self, url: str) -> int:
        words = _words(url)
        return max((len(w) for w in words), default=0)


class AvgWordLength(Feature):
    name = "avg_word_length"
    description = "Average length of alphanumeric tokens in the URL."

    def extract(self, url: str) -> float:
        words = _words(url)
        return sum(len(w) for w in words) / len(words) if words else 0.0
