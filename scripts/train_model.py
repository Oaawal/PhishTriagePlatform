"""
Train and evaluate PhishTriage's own scam classifier from collected data.

Data comes from the moderated training samples (Admin > Training data) and,
optionally, the seed set in tests/data/ng_messages.csv.

Usage:
    pip install -r requirements-train.txt

    # Download the reviewed samples from the live API and train:
    ADMIN_API_KEY=... python scripts/train_model.py --api https://phishtriageplatform.onrender.com

    # Or train from CSV files you already have (label,category_hint,text):
    python scripts/train_model.py --csv phishtriage_training.csv --csv tests/data/ng_messages.csv

Outputs (in --out, default models/):
    scam_model.joblib     the trained model (TF-IDF + logistic regression)
    metrics.json          cross-validated precision/recall vs the rules engine

The model is NOT used by the API yet. Wire it in only once metrics.json shows
it beats or usefully complements the rules engine on real data (aim for
1,000+ reviewed samples with both scam and safe examples).
"""
import argparse
import csv
import io
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import ENGINE_VERSION, analyze_text, redact_for_training  # noqa: E402

MIN_SAMPLES = 1000


def load_csv_text(text: str) -> list[tuple[int, str]]:
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        label = (r.get("label") or "").strip().lower()
        if label in ("scam", "spam"):
            y = 1
        elif label in ("legit", "safe", "ham"):
            y = 0
        else:
            continue
        txt = (r.get("text") or "").strip()
        if txt:
            rows.append((y, txt))
    return rows


def download(api: str) -> str:
    key = os.environ.get("ADMIN_API_KEY")
    if not key:
        sys.exit("Set ADMIN_API_KEY to download training data from the API.")
    req = urllib.request.Request(f"{api.rstrip('/')}/admin/training/export", headers={"X-API-Key": key})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read().decode("utf-8")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api", help="API base URL to download reviewed samples from")
    p.add_argument("--csv", action="append", default=[], help="CSV file(s) with label,category_hint,text")
    p.add_argument("--no-seed", action="store_true", help="Do not add tests/data/ng_messages.csv")
    p.add_argument("--out", default="models")
    args = p.parse_args()

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import FeatureUnion, Pipeline
    import joblib

    rows: list[tuple[int, str]] = []
    collected = 0
    if args.api:
        data = load_csv_text(download(args.api))
        collected += len(data)
        rows += data
    for path in args.csv:
        data = load_csv_text(Path(path).read_text(encoding="utf-8"))
        collected += len(data)
        rows += data
    if not args.no_seed:
        rows += load_csv_text((ROOT / "tests/data/ng_messages.csv").read_text(encoding="utf-8"))

    # Redact everything the same way, so seed and collected data look alike.
    rows = list({(y, redact_for_training(t)) for y, t in rows})
    y = [r[0] for r in rows]
    X = [r[1] for r in rows]
    n_scam, n_safe = sum(y), len(y) - sum(y)
    print(f"Samples: {len(rows)} ({n_scam} scam, {n_safe} safe); collected from users: {collected}")
    if min(n_scam, n_safe) < 5:
        sys.exit("Need at least 5 scam and 5 safe examples.")
    if collected < MIN_SAMPLES:
        print(f"WARNING: only {collected} collected samples. Results are not reliable until about {MIN_SAMPLES}.")

    model = Pipeline([
        ("features", FeatureUnion([
            ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, sublinear_tf=True)),
        ])),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
    ])

    folds = max(2, min(5, n_scam, n_safe))
    pred = cross_val_predict(model, X, y, cv=StratifiedKFold(folds, shuffle=True, random_state=42))
    rules = [1 if analyze_text(t)["risk"] != "Low" else 0 for t in X]

    def scores(p):
        tp = sum(1 for a, b in zip(y, p) if a == b == 1)
        fp = sum(1 for a, b in zip(y, p) if a == 0 and b == 1)
        fn = sum(1 for a, b in zip(y, p) if a == 1 and b == 0)
        return {
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "missed_scams": fn,
            "false_alarms": fp,
        }

    either = [max(a, b) for a, b in zip(pred, rules)]
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "engine_version": ENGINE_VERSION,
        "samples": len(rows),
        "collected_samples": collected,
        "scam": n_scam,
        "safe": n_safe,
        "cv_folds": folds,
        "model": scores(pred),
        "rules_engine": scores(rules),
        "model_or_rules": scores(either),
        "reliable": collected >= MIN_SAMPLES,
    }
    model.fit(X, y)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out / "scam_model.joblib")
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))
    print(f"Saved {out / 'scam_model.joblib'} and {out / 'metrics.json'}")


if __name__ == "__main__":
    main()
