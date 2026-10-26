# make_expected.py
# 2026 Joey Manani & Anchorfish Team
#
# Rebuild tests/expected.csv: 100 Legitimate + 100 Phishing rows from the training table plus model's proba
# Usage: python -m scripts.make_expected "<Assignment 2>/feature-extraction/datasets/features.csv"

import sys
from pathlib import Path
import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent

if len(sys.argv) != 2:
    sys.exit("Usage: python -m scripts.make_expected <path to Assignment 2 features.csv>")

training = pd.read_csv(sys.argv[1], keep_default_na=False)
training = training[training.type.isin(["Legitimate", "Phishing"])]
expected = training.groupby("type", group_keys=False).sample(100, random_state=30049)

model = joblib.load(ROOT / "models" / "final_hgb.joblib") 
expected["expected_probability"] = model.predict_proba(expected[list(model.feature_names_in_)])[:, 1]
expected.to_csv(ROOT / "tests" / "expected.csv", index=False)
print(f"Wrote {len(expected)} rows to tests/expected.csv")
