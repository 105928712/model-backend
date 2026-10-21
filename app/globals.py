from typing import Literal
from pathlib import Path


# EXPORTS
MAX_URL_LENGTH: int             = 2048                                                    # longest URL accepted
MAX_BODY_BYTES: int             = 16 * 1024                                               # biggest request body; a 2048-char URL is at most 8 KiB as UTF-8 plus JSON. The batch route allows this much per URL
BATCH_RETRY_AFTER: int          = 5                                                       # seconds a client is told to wait when every batch slot is busy
TRAINING_URL_LENGTH: int        = 923                                                     # 99.99th percentile of the 786,062 training URL lengths
RISK_BAND                       = Literal["low", "medium", "high"]                        # allocation bands for risk assessment
FEATURE_VALUE                   = float | int | bool | str                                # type for individual feature values
WARNINGS                        = Literal["unknown_suffix", "longer_than_training_urls"]  # types of warnings that can be generated


MODELS_DIRECTORY: Path          = Path(__file__).resolve().parent.parent / "models"
LABEL                           = Literal["phishing", "legitimate"]                       # MUST be either of these two, hence a literal used here
