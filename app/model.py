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
from sqlalchemy import text
from .database import engine
from .globals import MODELS_DIRECTORY, LABEL
from .settings import MODEL_HASH_CHECK

# Typical legitimate value of every feature (median, or most common for true/false), from scripts/export_chart_data.py
LEGIT_BASELINE: dict = json.loads((MODELS_DIRECTORY / "legit_baseline.json").read_text())


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

    def contributions(self, url: str) -> dict[str, float] | None:
        """How much each feature raised (+) or lowered (-) the risk: score again with that one feature set to its
        typical legitimate value. Measured in log-odds, because near p = 1 probabilities saturate and every change
        looks like 0. Only features that changed the score are returned. None for raw-text models"""
        columns = getattr(self.classifier, "feature_names_in_", None)
        if columns is None:
            return None
        row = urls_to_features([url], list(columns))
        variants = pd.concat([row] + [row.assign(**{column: LEGIT_BASELINE[column]}) for column in columns], ignore_index=True)
        log_odds = self.classifier.decision_function(variants)
        changes = {column: round(float(log_odds[0] - log_odds[i]), 3) for i, column in enumerate(columns, start=1)}
        return {column: change for column, change in sorted(changes.items(), key=lambda item: -abs(item[1])) if change}

    def get_model_input(self, urls: list[str]) -> pd.DataFrame | list[str]:
        """Feature-table models list the columns they were trained on in feature_names_in_ and raw-text models don't use this"""
        
        # Check if we can determine the columns that the model was trained on otherwise we will be returning just the canonical URLs
        columns = getattr(self.classifier, "feature_names_in_", None)
        if columns is None:
            return [canonical_url(url) for url in urls]
        return urls_to_features(urls, list(columns))


def load_model(name: str | None = None) -> PhishingModel:
    """Load a model from the models table (the active one by default). Unknown name raises KeyError"""
    with engine.connect() as db:
        if name is None:
            entry = db.execute(text("SELECT name, file, sha256, threshold FROM models WHERE active")).mappings().first()
        else:
            entry = db.execute(text("SELECT name, file, sha256, threshold FROM models WHERE name = :name"), {"name": name}).mappings().first()
    if entry is None:
        raise KeyError(name or "no active model")
    name = entry["name"]

    path = MODELS_DIRECTORY / entry["file"]
    data = path.read_bytes()

    # Because use of joblib deserialises the file and can run abitrary code, we read the bytes of the file manually
    # and run a hash check and compare it to what's in the registry right now and refuse to deserialise if it differs.

    if MODEL_HASH_CHECK and hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError(f"Hash mismatch when loading {name} from {path}")

    return PhishingModel(name, entry["threshold"], joblib.load(path))
