# base.py
# 2026 Joey Manani & Anchorfish Team
# Base feature extractor

from typing import Any
from abc import ABC, abstractmethod

class Feature(ABC):
    """Base class for URL feature extractors."""

    name = ""
    description = ""

    def __init__(self, url: str) -> None:
        self.url = url

    @abstractmethod
    def extract(self, url: str) -> Any:
        """Extract this feature from a URL."""
        raise NotImplementedError

    @property
    def value(self) -> Any:
        """The feature extracted from self.url."""
        return self.extract(self.url)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(url={self.url!r}): {self.value}"
