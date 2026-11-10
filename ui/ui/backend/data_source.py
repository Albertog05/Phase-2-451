"""Where the records to scan come from.

NOW: random rows from the saved test set (splits.joblib), which have true labels.
LATER (live traffic): replace get_records() so it turns captured packets into the same
feature rows (same columns, same imputer and scaler) and returns labels as None.
"""
import os
from pathlib import Path
import joblib

# repo root = two folders above ui/backend, where the .joblib files are saved
ROOT = Path(os.environ.get("MODEL_DIR", Path(__file__).resolve().parents[2]))
_X = None
_y = None


def load_test_set():
    global _X, _y
    d = joblib.load(ROOT / "splits.joblib")
    _X, _y = d["X_test"], d["y_test"]  # drop the train and validation parts


def max_records():
    return len(_X)


def get_records(n):
    """Return (features, labels). labels is None when the truth is unknown."""
    rows = _X.sample(n=min(n, len(_X)))
    return rows, _y.loc[rows.index].to_numpy()
