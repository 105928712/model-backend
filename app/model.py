# model.py
# 2026 Joey Manani & Anchorfish Team
# Loads a registered model pipeline and scores URLs with it

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol
import joblib
import numpy as np
import pandas as pd
from features.utils import canonical_url
from .preprocessing import urls_to_features
from .globals import MODELS_DIRECTORY, REGISTRY_PATH, LABEL


class Classifier(Protocol):
    """Interface: any trained classifier including pipeline that uses features or just the raw URL"""
    def predict_proba(self, model_input: pd.DataFrame | list[str]) -> np.ndarray:
        raise NotImplementedError # Linter giving me grief.


@dataclass(frozen=True)
class Prediction:
    """A phishing prediction, with a probability and label (phishing or legitimate)"""
    probability: float
    label: LABEL



@dataclass(frozen=True)
class PhishingModel:
    """A phishing model, with a name, a threshold and a classifier"""
    name: str
    threshold: float
    classifier: Classifier

    def __post_init__(self) -> None:
        """Check that the threshold is between 0 and 1."""
        if not 0 < self.threshold < 1:
            raise ValueError(f"Threshold for model {self.name} must be between 0 and 1, but got {self.threshold}")        

    def predict(self, url: str) -> Prediction:
        """Score a URL with the classifier pipeline and return a prediction object"""
        return self.predict_many([url])[0]

    def predict_many(self, urls: list[str]) -> list[Prediction]:
        """Score several URLs in one classifier call, much cheaper than one call per URL"""
        probabilities = self.classifier.predict_proba(self.get_model_input(urls))[:, 1] # column 1 is P(phishing)
        # label is based on the threshold
        return [Prediction(float(p), "phishing" if p > self.threshold else "legitimate") for p in probabilities]

    def get_model_input(self, urls: list[str]) -> pd.DataFrame | list[str]:
        """Feature-table models list the columns they were trained on in feature_names_in_ and raw-text models don't use this"""
        
        # Check if we can determine the columns that the model was trained on otherwise we will be returning just the canonical URLs
        columns = getattr(self.classifier, "feature_names_in_", None)
        if columns is None:
            return [canonical_url(url) for url in urls]
        return urls_to_features(urls, list(columns))


def load_model(name: str | None = None) -> PhishingModel:
    """Load a model from the registry (the registry's active model by default)"""
    registry = json.loads(REGISTRY_PATH.read_text())

    name = name or registry["active"]
    entry = registry["models"][name]

    path = MODELS_DIRECTORY / entry["file"]
    data = path.read_bytes()

    # Because use of joblib deserialises the file and can run abitrary code, we read the bytes of the file manually
    # and run a hash check and compare it to what's in the registry right now and refuse to deserialise if it differs.

    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError(f"Hash mismatch when loading {name} from {path}")

    return PhishingModel(name, entry["threshold"], joblib.load(path))
