# test_parity.py
# 2026 Joey Manani & Anchorfish Team
# The API must build the same features as training and give the notebook's probability.
#
# expected.csv: 100 Legitimate + 100 Phishing rows (random_state=30049) from Assignment 2's features.csv 
# with new column expected_probability = final_hgb's score on those stored features (what the model scored)

from pathlib import Path
import pandas as pd
import pytest

EXPECTED = pd.read_csv(Path(__file__).parent / "expected.csv", keep_default_na=False).to_dict("records")


@pytest.fixture(scope="module")
def results(client) -> list[dict]:
    """The API's answer for every expected URL (scores every URL)"""
    return [client.post("/api/check", json={"url": row["url"]}).json() for row in EXPECTED]


def test_features_match_training(results):
    for result, row in zip(results, EXPECTED):
        training = {name: row[name] for name in result["features"]}
        assert result["features"] == pytest.approx(training), row["url"]


def test_probability_matches_notebook(results):
    for result, row in zip(results, EXPECTED):
        assert result["probability"] == pytest.approx(row["expected_probability"], abs=1e-12), row["url"]
