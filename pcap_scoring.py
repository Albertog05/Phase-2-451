#pcap_scoring.py
#Omar Juarez
#CECS 451 Phase 2: scores a raw PCAP with one of the saved models and reports flagged windows, alerts and reasons.
#Shared by the web UI (ui/backend/pcap_routes.py) and evaluate_captures.py.
#Needs pcap_features.py (and the dpkt package) next to it, plus preprocess.joblib and the model files.
#
#Two levels of result, because one flagged window is weak evidence:
#  flagged window = malware probability >= the model's saved threshold
#  alert          = at least ALERT_K of the last ALERT_N windows are flagged (same rule as compare_models.py)
import os
import numpy as np
import pandas as pd
import joblib
from pcap_features import pcap_to_rows, scale_rows

MODEL_FILES = {'A': 'best_model.joblib', 'B': 'best_model_realworld.joblib', 'C': 'best_model_c.joblib'}
MODEL_NOTES = {
    'A': 'Trained on sandbox data only.',
    'B': 'Sandbox data plus real benign traffic.',
    'C': 'Like B, without TTL, Rate and IAT (device dependent or estimated). Recommended default for real traffic.',
}
ESTIMATED = ['Time_To_Live', 'Rate', 'IAT', 'LLC']   #features pcap_features.py has to guess, or that depend on the device
ALERT_N = 10
ALERT_K = 5


def load_bundles(root):
    """Load whichever of the model files exist in root. Returns {'A': bundle, ...}."""
    out = {}
    for key, fname in MODEL_FILES.items():
        path = os.path.join(root, fname)
        if os.path.exists(path):
            out[key] = joblib.load(path)
    return out


def load_preprocess(root):
    return joblib.load(os.path.join(root, 'preprocess.joblib'))


def alert_flags(flag, n=ALERT_N, k=ALERT_K):
    """True where at least k of the last n windows are flagged."""
    counts = pd.Series(np.asarray(flag).astype(int)).rolling(n, min_periods=1).sum().to_numpy()
    return counts >= k


def count_runs(mask):
    """Number of separate stretches of True (for alerts: separate alert episodes)."""
    m = np.asarray(mask).astype(int)
    if m.size == 0:
        return 0
    return int((np.diff(np.concatenate([[0], m])) == 1).sum())


def timeline(flag, in_alert, bins=200):
    """Shrink the scan to at most `bins` cells: 0 = nothing, 1 = flagged window(s), 2 = inside an alert."""
    n = len(flag)
    if n == 0:
        return []
    edges = np.linspace(0, n, min(bins, n) + 1).astype(int)
    cells = []
    for a, b in zip(edges[:-1], edges[1:]):
        b = max(b, a + 1)
        cells.append(2 if in_alert[a:b].any() else (1 if flag[a:b].any() else 0))
    return cells


def window_reasons(Z, bundle, top=3, min_z=1.0):
    """For every window: the features that are both unusual (large z-score against the training data) and important
    to the model. This points at what stands out. It is not an exact explanation of the model's decision."""
    cols = bundle['columns']
    M = Z[cols].to_numpy(dtype=float)
    imp = getattr(bundle['model'], 'feature_importances_', None)
    imp = np.ones(len(cols)) if imp is None else np.asarray(imp, dtype=float)
    order = np.argsort(-(np.abs(M) * imp), axis=1)[:, :top]
    reasons = []
    for i in range(len(M)):
        parts = [f"{cols[j]} {'high' if M[i, j] > 0 else 'low'} ({M[i, j]:+.1f} sd)"
                 for j in order[i] if abs(M[i, j]) >= min_z]
        reasons.append('; '.join(parts) if parts else 'nothing unusual')
    return reasons


def score_capture(path, bundle, pre, alert_n=ALERT_N, alert_k=ALERT_K):
    """Score one PCAP. Returns (summary dict, per-window report DataFrame, timeline list)."""
    rows, dropped = pcap_to_rows(path)
    n = len(rows)
    thr = float(bundle.get('threshold', 0.5))
    cols = bundle['columns']
    summary = {'windows': n, 'dropped_packets': int(dropped), 'model_name': bundle['name'], 'threshold': thr,
               'alert_rule': f'{alert_k} of the last {alert_n} windows', 'warnings': []}
    if n == 0:
        summary.update({'flagged_windows': 0, 'flagged_pct': 0.0, 'alert_windows': 0, 'alert_pct': 0.0,
                        'alert_episodes': 0, 'capture_seconds': 0.0, 'alerts_per_hour': None, 'status': 'No data'})
        summary['warnings'].append('The capture has fewer than 10 packets, so there is no complete window to score.')
        return summary, pd.DataFrame(), []

    Z = scale_rows(rows, pre)
    proba = bundle['model'].predict_proba(Z[cols])[:, 1]
    flag = proba >= thr
    in_alert = alert_flags(flag, alert_n, alert_k)
    start = rows['window_start'].to_numpy(dtype=float) if 'window_start' in rows else np.full(n, np.nan)
    seconds = float(start[-1] - start[0]) if n > 1 and np.isfinite(start[[0, -1]]).all() else 0.0
    episodes = count_runs(in_alert)

    summary.update({
        'flagged_windows': int(flag.sum()), 'flagged_pct': round(float(flag.mean() * 100), 1),
        'alert_windows': int(in_alert.sum()), 'alert_pct': round(float(in_alert.mean() * 100), 1),
        'alert_episodes': episodes, 'capture_seconds': round(seconds, 1),
        'alerts_per_hour': round(episodes / (seconds / 3600), 2) if seconds >= 60 else None,
        'status': 'Alerts raised' if episodes else ('Some windows flagged' if flag.any() else 'Clean'),
    })

    used_estimated = [c for c in ESTIMATED if c in cols]
    if used_estimated:
        summary['warnings'].append('Estimated or device dependent features used by this model: '
                                   + ', '.join(used_estimated) + '. Model C drops TTL, Rate and IAT.')
    if summary['flagged_pct'] > 25:
        summary['warnings'].append('A large share of windows is flagged. On a normal network this usually means the '
                                   'traffic looks different from the training data (false alarms), not necessarily malware.')
    summary['warnings'].append('The models were trained on IoT malware recorded in a sandbox. They are not validated on '
                               'other malware families or other networks.')

    report = pd.DataFrame({
        'window': np.arange(n),
        'start_time': pd.to_datetime(start, unit='s', utc=True).strftime('%Y-%m-%d %H:%M:%S') if np.isfinite(start).all() else '',
        'malware_probability': np.round(proba, 4),
        'flagged': flag,
        'in_alert': in_alert,
        'reasons': window_reasons(Z, bundle),
    })
    report = pd.concat([report, rows.drop(columns=['window_start'], errors='ignore')], axis=1)
    return summary, report, timeline(flag, in_alert)
