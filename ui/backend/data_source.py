"""
Where the records to scan come from.

NOW: random rows from the saved test set (splits.joblib), which have true labels.
LATER (live traffic): replace get_records() so it turns captured packets into the same
feature rows (same columns, same imputer and scaler) and returns labels as None.
"""
import os
from pathlib import Path
import pandas as pd

# repo root = two folders above ui/backend, where the .joblib files are saved
ROOT = Path(os.environ.get("MODEL_DIR", Path(__file__).resolve().parents[2]))
_X = None
_y = None
_ids = None

def load_test_set():
    global _X, _y, _ids
    df = pd.read_csv(ROOT / "demo_samples.csv")  # window_id, feature columns, true_label
    _ids = df["window_id"]
    _y = (df["true_label"] == "MALWARE").astype(int)
    _X = df.drop(columns=["window_id", "true_label"])


def max_records():
    return len(_X)

def get_ids(index):
    return _ids.loc[index].to_numpy()

def get_records(n):
    """Return (features, labels). labels is None when the truth is unknown."""
    rows = _X.sample(n=min(n, len(_X)))
    return rows, _y.loc[rows.index].to_numpy()
