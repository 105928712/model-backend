from features.utils import get_host, is_ip, normalise_url, psl
from .globals import RISK_BAND, WARNINGS, TRAINING_URL_LENGTH


def training_domain_warnings(url: str) -> list[str]:
    """Things about a URL the model never saw in training. The URL is still scored, but the score is less trustworthy."""
    host = get_host(normalise_url(url))
    warnings = []
    if not is_ip(host) and not psl.publicsuffix(host, accept_unknown=False):
        warnings.append(WARNINGS["unknown_suffix"])
    if len(url) > TRAINING_URL_LENGTH:
        warnings.append(WARNINGS["longer_than_training_urls"])
    return warnings


def risk_band(probability: float, threshold: float) -> RISK_BAND:
    """High means flagged as phishing.
    Medium is the legitimate side but within half the threshold of it"""
    if probability > threshold:
        return "high"
    if probability > threshold / 2:
        return "medium"
    return "low"