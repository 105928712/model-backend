from typing import Literal
from pathlib import Path


# EXPORTS
MAX_URL_LENGTH: int             = 2048                                                    # longest URL accepted
TRAINING_URL_LENGTH: int        = 923                                                     # 99.99th percentile of the 786,062 training URL lengths
RISK_BAND                       = Literal["low", "medium", "high"]                        # allocation bands for risk assessment
FEATURE_VALUE                   = float | int | bool | str                                # type for individual feature values
WARNINGS                        = Literal["unknown_suffix", "longer_than_training_urls"]  # types of warnings that can be generated


MODELS_DIRECTORY: Path          = Path(__file__).resolve().parent.parent / "models"
REGISTRY_PATH: Path             = MODELS_DIRECTORY / "registry.json"                      # will be database in near future
LABEL                           = Literal["phishing", "legitimate"]                       # MUST be either of these two, hence a literal used here
