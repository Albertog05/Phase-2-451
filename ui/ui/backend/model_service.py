"""Loads the winning model and scores records with the saved threshold."""
import time
import joblib
from data_source import ROOT, get_records

_bundle = None


def load_model():
    global _bundle
    _bundle = joblib.load(ROOT / "best_model.joblib")


def model_info():
    return {"name": _bundle["name"], "threshold": _bundle.get("threshold", 0.5)}


def scan(n):
    X, y = get_records(n)
    X = X[_bundle["columns"]]  # same column order as training
    t0 = time.perf_counter()
    proba = _bundle["model"].predict_proba(X)[:, 1]
    seconds = time.perf_counter() - t0
    pred = (proba >= _bundle.get("threshold", 0.5)).astype(int)
    malicious = int(pred.sum())
    result = {
        "records": int(len(X)),
        "seconds": round(seconds, 3),
        "malicious": malicious,
        "status": "Threats found" if malicious else "Clean",
        "missed": None, "false_alarms": None, "accuracy": None,
    }
    if y is not None:  # only possible with labeled (test) data
        result["missed"] = int(((pred == 0) & (y == 1)).sum())
        result["false_alarms"] = int(((pred == 1) & (y == 0)).sum())
        result["accuracy"] = round(float((pred == y).mean()), 4)
    return result
