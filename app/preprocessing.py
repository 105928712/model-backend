# preprocessing.py
# 2026 Joey Manani & Anchorfish Team
# URL to feature table transformation, the same steps used in training

import pandas as pd
import features
from features.utils import canonical_url
from .globals import FEATURE_VALUE

def url_features(url: str) -> dict[str, FEATURE_VALUE]:
    """Every feature the extractor knows about for one URL, cleaned the same way as in training."""
    return features.extract_features(canonical_url(url))


def urls_to_features(urls: list[str], columns: list[str]) -> pd.DataFrame:
    """Transform a list of URLs to a feature table, using the same steps used in training."""
    return pd.DataFrame([url_features(url) for url in urls])[columns]
