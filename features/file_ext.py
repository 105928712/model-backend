# malicious_extensions.py
# 2026 Joey Manani & Anchorfish Team
# Malicious file extension extractor

from .base import Feature
from .utils import split_url

MALICIOUS_EXTENSIONS = frozenset({
    "exe",
    "scr",
    "msi",
    "bat",
    "cmd",
    "com",
    "pif",
    "cpl",
    "dll",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "ps1",
    "psm1",
    "hta",
})


class HasMaliciousFileExtension(Feature):
    """Checks whether the URL path contains a potentially executable file extension."""
    
    name = "has_malicious_file_extension"
    description = "Whether the URL path contains a potentially malicious file extension"

    def extract(self, url: str) -> int:
        parts = split_url(url)

        # Only examine the path, not the domain or query
        path = parts.path if parts else ""

        # Get the final part of the path
        filename = path.rstrip("/").split("/")[-1]

        # Make sure the filename contains an extension
        if "." not in filename:
            return 0

        extension = filename.rsplit(".", 1)[-1].lower()

        if extension in MALICIOUS_EXTENSIONS:
            return 1

        return 0