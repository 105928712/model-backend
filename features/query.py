#query.py
# 2026 Joey Manani & Anchorfish Team
# Query extractors  

from urllib.parse import parse_qsl
from .base import Feature
from .utils import split_url


def _query(url: str) -> str:
    """URL query string, or "" if the URL can't be parsed."""
    parts = split_url(url)
    return parts.query if parts else ""

class QueryLength(Feature):
    name = "query_length"
    description = "The character length of the URL query string."

    def extract(self, url: str) -> int:
        return len(_query(url))

class NumQueryComponents(Feature):
    name = "num_query_components"
    description = "The number of query components in the URL."

    def extract(self, url: str) -> int:
        query = _query(url)

        if not query: 
            return 0
        
        return len(parse_qsl(query, keep_blank_values=True))