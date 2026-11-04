# export_chart_data.py
# 2026 Joey Manani & Anchorfish Team

# One-off export from the training feature table

import json
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.inspection import permutation_importance
from sklearn.preprocessing import StandardScaler
from app.globals import MODELS_DIRECTORY
from app.model import load_model

SEED = 9238045
SAMPLE_SIZE = 20_000        # rows used for importance and clusters; the full table is 786k
SCATTER_POINTS = 1_500      # dots sent to the browser
CLUSTERS = 4
LENGTH_BIN = 10             # URL length histogram bin width
LENGTH_MAX = 200            # longer URLs go in one "200+" bin
EXAMPLES = 3                # phishing URLs shown per feature on Results
EXAMPLE_LENGTH = (20, 70)   # short enough to read in one line


def baseline(legit: pd.DataFrame) -> dict:
    """Median for numbers, most common value for true/false"""
    return {col: bool(legit[col].mode()[0]) if legit[col].dtype == bool else float(legit[col].median()) for col in legit.columns}


def importance(model, sample: pd.DataFrame, y: np.ndarray) -> list[dict]:
    """How much ROC AUC drops when each feature is shuffled. HGB has no built-in importances"""
    result = permutation_importance(model, sample, y, scoring="roc_auc", n_repeats=3, random_state=SEED, n_jobs=-1)
    rows = [{"feature": f, "importance": round(float(m), 5)} for f, m in zip(sample.columns, result.importances_mean)]
    return sorted(rows, key=lambda r: r["importance"], reverse=True)


def length_histogram(lengths: pd.Series, labels: pd.Series) -> list[dict]:
    bins = lengths.clip(upper=LENGTH_MAX) // LENGTH_BIN * LENGTH_BIN
    counts = pd.crosstab(bins, labels)
    return [{"from": int(b), "to": None if b >= LENGTH_MAX else int(b + LENGTH_BIN),
             "phishing": int(counts.at[b, "Phishing"]), "legitimate": int(counts.at[b, "Legitimate"])} for b in counts.index]


def clusters(sample: pd.DataFrame, labels: pd.Series) -> dict:
    """k-means on scaled features, flattened to 2D with PCA so it can be drawn"""
    scaled = StandardScaler().fit_transform(sample.astype(float))
    groups = KMeans(n_clusters=CLUSTERS, n_init=10, random_state=SEED).fit_predict(scaled)
    pca = PCA(n_components=2, random_state=SEED)
    xy = pca.fit_transform(scaled)
    phishing = (labels == "Phishing").to_numpy()
    summary = [{"cluster": c, "size": int((groups == c).sum()), "phishing_share": round(float(phishing[groups == c].mean()), 4)} for c in range(CLUSTERS)]
    pick = np.random.default_rng(SEED).choice(len(sample), SCATTER_POINTS, replace=False)
    points = [{"x": round(float(xy[i, 0]), 3), "y": round(float(xy[i, 1]), 3), "cluster": int(groups[i]),
               "label": "phishing" if phishing[i] else "legitimate", "url": sample.index[i]} for i in pick]
    return {"explained_variance": [round(float(v), 4) for v in pca.explained_variance_ratio_], "summary": summary, "points": points}


def examples(table: pd.DataFrame, columns: list[str], labels: pd.Series) -> dict:
    """Per feature: the typical legitimate value, and a few real phishing URLs above it ("high") and below it ("low").
    Results picks the side the checked link is on. Rare values first (past the legit 95th/5th percentile), else any"""
    legit, phishing = table[labels == "Legitimate"], table[labels == "Phishing"]
    phishing = phishing[phishing["url_length"].between(*EXAMPLE_LENGTH)]
    typical = baseline(legit[columns])

    def pick(rows: pd.DataFrame) -> list[dict]:
        rows = rows.sample(min(EXAMPLES, len(rows)), random_state=SEED)
        return [{"url": url, "root_domain": row.root_domain, "tld": row.tld} for url, row in rows.iterrows()]

    picked = {}
    for col in columns:
        values = phishing[col].astype(float)
        sides = {"high": (values > legit[col].astype(float).quantile(0.95), values > typical[col]),
                 "low": (values < legit[col].astype(float).quantile(0.05), values < typical[col])}
        picked[col] = {"typical": typical[col],
                       **{side: pick(phishing[rare] if rare.sum() >= EXAMPLES else phishing[any_]) for side, (rare, any_) in sides.items()}}
    return picked


def main(features_csv: str, chart_out: str) -> None:
    model = load_model("final_hgb").classifier  # goes through the registry hash check, never a raw joblib.load
    columns = list(model.feature_names_in_)
    everything = pd.read_csv(features_csv, usecols=["url", "type", "root_domain", "tld", *columns], keep_default_na=False, index_col="url")
    table = everything[everything["type"].isin(["Phishing", "Legitimate"])]  # malware and defacement only show in class balance
    X, labels = table[columns], table["type"]

    (MODELS_DIRECTORY / "legit_baseline.json").write_text(json.dumps(baseline(X[labels == "Legitimate"]), indent=2))

    sample = X.sample(SAMPLE_SIZE, random_state=SEED)
    sample_labels = labels.loc[sample.index]
    charts = {
        "source": f"{len(everything):,} URLs from features.csv; charts other than class balance use the {len(table):,} phishing and legitimate ones; importance and clusters use a random {SAMPLE_SIZE:,}",
        "class_balance": everything["type"].str.lower().value_counts().to_dict(),
        "feature_importance": importance(model, sample, (sample_labels == "Phishing").to_numpy()),
        "url_length": length_histogram(X["url_length"], labels),
        "clusters": clusters(sample, sample_labels),
    }
    Path(chart_out).parent.mkdir(parents=True, exist_ok=True)
    Path(chart_out).write_text(json.dumps(charts))
    Path(chart_out).with_name("featureExamples.json").write_text(json.dumps(examples(table, columns, labels)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python -m scripts.export_chart_data <features.csv> <chart json out>")
    main(sys.argv[1], sys.argv[2])
