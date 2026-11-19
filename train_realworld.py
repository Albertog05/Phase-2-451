#train_realworld.py
#Alberto Gaspar
#CECS 451 Phase 2: Model B = the same tuned Random Forest, retrained with real benign traffic added to the training data.
#Model A (best_model.joblib) is NOT changed. Model B is saved as best_model_realworld.joblib.
#The capture is cut in time order: first 60% train, next 13% validation, last 23% held-out test (small gaps between).
#Usage: python train_realworld.py real_benign.pcap          (run as many times as you like)
#       python train_realworld.py real_benign.pcap --final  (also scores the sandbox TEST set for Model B, do this ONCE)

import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import recall_score, precision_score, f1_score
from WS_pcap import pcap_to_rows, scale_rows

HERE  = os.path.dirname(os.path.abspath(__file__))
args  = [a for a in sys.argv[1:] if not a.startswith('--')]
PCAP  = args[0] if args else os.path.join(HERE, 'real_benign.pcap')
FINAL = '--final' in sys.argv

d   = joblib.load(os.path.join(HERE, 'splits.joblib'))
pre = joblib.load(os.path.join(HERE, 'preprocess.joblib'))
A   = joblib.load(os.path.join(HERE, 'best_model.joblib'))
cols, thr_A = pre['columns'], A.get('threshold', 0.5)

def scores(y, proba, thr):
    pred = (proba >= thr).astype(int)
    return recall_score(y, pred), precision_score(y, pred), f1_score(y, pred)

#------------------------REAL WINDOWS, SPLIT IN TIME ORDER-----------------------------------------
rows, _ = pcap_to_rows(PCAP)
R = scale_rows(rows, pre)
n = len(R)
R_train = R.iloc[:int(n * 0.60)]
R_val   = R.iloc[int(n * 0.62):int(n * 0.75)]
R_test  = R.iloc[int(n * 0.77):]
print(f"{os.path.basename(PCAP)}: {n} windows -> train {len(R_train)} | validation {len(R_val)} | held-out test {len(R_test)}")

#------------------------MODEL B: same tuned settings as Model A, more benign data----------------
X_B = pd.concat([d['X_train'][cols], R_train], ignore_index=True)
y_B = np.concatenate([d['y_train'].to_numpy(), np.zeros(len(R_train), dtype=int)])   #real windows are benign = 0
B = clone(A['model'])
B.fit(X_B, y_B)

#Model B threshold: best F1 on sandbox validation + real validation windows together
Xv = pd.concat([d['X_val'][cols], R_val], ignore_index=True)
yv = np.concatenate([d['y_val'].to_numpy(), np.zeros(len(R_val), dtype=int)])
pv = B.predict_proba(Xv)[:, 1]
thr_B = max(np.arange(0.1, 0.95, 0.05), key=lambda t: scores(yv, pv, t)[2])
thr_B = round(float(thr_B), 2)
print(f"Model A threshold: {thr_A} | Model B threshold (best F1 on validation): {thr_B}")

#------------------------COMPARE-------------------------------------------------------------------
y_sv = d['y_val'].to_numpy()
print("\n--- SANDBOX VALIDATION (malware + benign) ---")
print("model   threshold  recall  precision  F1")
for name, m, t in [('A', A['model'], thr_A), ('B', B, thr_B)]:
    r, p, f = scores(y_sv, m.predict_proba(d['X_val'][cols])[:, 1], t)
    print(f"{name:<7} {t:<10} {r:.4f}  {p:.4f}     {f:.4f}")

print(f"\n--- REAL HELD-OUT WINDOWS ({len(R_test)} benign windows the model never saw) ---")
print("model   threshold  falsely flagged")
for name, m, t in dict.fromkeys([('A', A['model'], thr_A), ('A', A['model'], 0.5), ('B', B, thr_B), ('B', B, 0.5)]):
    flagged = (m.predict_proba(R_test)[:, 1] >= t).sum()
    print(f"{name:<7} {t:<10} {flagged} of {len(R_test)} ({flagged / len(R_test) * 100:.1f}%)")

if FINAL:
    print("\n--- SANDBOX TEST SET, MODEL B (scored once) ---")
    r, p, f = scores(d['y_test'].to_numpy(), B.predict_proba(d['X_test'][cols])[:, 1], thr_B)
    print(f"   Recall: {r:.4f} | Precision: {p:.4f} | F1: {f:.4f}")

joblib.dump({'model': B, 'name': 'Random Forest (real benign added)', 'columns': A['columns'], 'threshold': thr_B},
            os.path.join(HERE, 'best_model_realworld.joblib'))
print("\nSaved best_model_realworld.joblib")