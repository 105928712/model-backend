# preprocessing.py
# 2026 Joey Manani & Anchorfish Team
# URL to feature table transformation, the same steps used in training

import pandas as pd
import features
from features.utils import canonical_url

def urls_to_features(urls: list[str], columns: list[str]) -> pd.DataFrame:
    """Transform a list of URLs to a feature table, using the same steps used in training."""
    rows = [features.extract_features(canonical_url(url)) for url in urls]
    return pd.DataFrame(rows)[columns]
