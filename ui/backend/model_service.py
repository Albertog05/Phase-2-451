"""
Loads the winning model and scores records with the saved threshold.
"""
import time
import joblib
import pandas as pd
from data_source import ROOT, get_records, get_ids

_bundle = None


def load_model():
    global _bundle
    _bundle = joblib.load(ROOT / "best_model.joblib")


def model_info():
    return {"name": _bundle["name"], "threshold": _bundle.get("threshold", 0.5)}

def _severity(score, flagged):
    if not flagged:
        return "Clean"
    return "High" if score >= 80 else "Medium" if score >= 50 else "Low"


def _top_features(n_top=5):
    """Trees and forests have feature_importances_; logistic regression has coef_."""
    model, cols = _bundle["model"], _bundle["columns"]
    if hasattr(model, "feature_importances_"):
        imp = pd.Series(model.feature_importances_, index=cols)
    elif hasattr(model, "coef_"):
        imp = pd.Series(abs(model.coef_[0]), index=cols)
        imp = imp / imp.sum()
    else:
        return []
    return [{"feature": name, "importance": round(float(v), 3)}
            for name, v in imp.nlargest(n_top).items()]

def scan(n):
    X, y = get_records(n)
    X = X[_bundle["columns"]]  # same column order as training
    t0 = time.perf_counter()
    proba = _bundle["model"].predict_proba(X)[:, 1]
    seconds = time.perf_counter() - t0
    thr = _bundle.get("threshold", 0.5)
    pred = (proba >= thr).astype(int)
    scores = (proba * 100).round(1)
    labels = y if y is not None else [None] * len(X)
    windows = [{"window_id": str(i), "score": float(s), "flagged": bool(p >= thr),
                "severity": _severity(s, p >= thr),
                "true_label": None if t is None else ("MALWARE" if t == 1 else "Benign")}
               for i, s, p, t in zip(get_ids(X.index), scores, proba, labels)]
    windows.sort(key=lambda w: w["score"], reverse=True)
    malicious = int(pred.sum())
    result = {
        "records": int(len(X)),
        "seconds": round(seconds, 3),
        "malicious": malicious,
        "status": "Threats found" if malicious else "Clean",
        "missed": None, "false_alarms": None, "accuracy": None,
        "windows": windows,
        "top_features": _top_features(),
    }
    if y is not None:  # only possible with labeled (demo) data
        result["missed"] = int(((pred == 0) & (y == 1)).sum())
        result["false_alarms"] = int(((pred == 1) & (y == 0)).sum())
        result["accuracy"] = round(float((pred == y).mean()), 4)
    return result
