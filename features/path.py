#path.py
# 2026 Joey Manani & Anchorfish Team
# Path extractors

from .base import Feature
from .utils import split_url


def _path(url: str) -> str:
    """URL path, or "" if the URL can't be parsed."""
    parts = split_url(url)
    return parts.path if parts else ""

class PathLevel(Feature):
    name = "path_level"
    description = "The depth of the URL path."

    def extract(self, url: str) -> int:
        path = _path(url).strip("/")
        if not path:
            return 0
        return len(path.split("/"))

class PathLength(Feature):
    name = "path_length"
    description = "The character length of the URL path."

    def extract(self, url: str) -> int:
        return len(_path(url))

class DoubleSlashPath(Feature):
    name = "double_slash_path"
    description = "Whether the URL path contains a double slash (//)."

    def extract(self, url: str) -> int:
        return int("//" in _path(url))
