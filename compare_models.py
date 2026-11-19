#CECS 451 Phase2: Model C = Model B's recipe without environment-dependent features, then A vs B vs C on every capture,
#each scored two ways: single windows, and "alerts" (at least ALERT_K of the last ALERT_N windows flagged).
#Needs in this folder: splits.joblib, preprocess.joblib, best_model.joblib (A), best_model_realworld.joblib (B),
#real_benign.pcap, second_session.pcap, mirai_test.pcap. Usage: python compare_models.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import recall_score, f1_score
from WS_pcap import pcap_to_rows, scale_rows

DROP = ['Time_To_Live', 'Rate', 'IAT'] #features that depend on the device/network, or that are my estimates
ALERT_N = 10   #look at the last N windows
ALERT_K = 5  # alert when at least K of them are flagged

HERE = os.path.dirname(os.path.abspath(__file__))
load = lambda f: joblib.load(os.path.join(HERE, f))
d, pre, A, B = load('splits.joblib'), load('preprocess.joblib'), load('best_model.joblib'), load('best_model_realworld.joblib')
all_cols = pre['columns']
colsC = [c for c in all_cols if c not in DROP]
print("Model C drops:", DROP, "| features left:", len(colsC))

#----------------CAPTURES: real_benign is cut exactly like train_realworld.py---------------
R = scale_rows(pcap_to_rows(os.path.join(HERE, 'real_benign.pcap'))[0], pre)
n = len(R)
R_train, R_val, R_test = R.iloc[:int(n * 0.60)], R.iloc[int(n * 0.62):int(n * 0.75)], R.iloc[int(n * 0.77):]
captures = {'benign: real_benign end': R_test}
for label, f in [('benign: second_session', 'second_session.pcap'), ('MALWARE: mirai_test', 'mirai_test.pcap')]:
    p = os.path.join(HERE, f)
    if os.path.exists(p):
        captures[label] = scale_rows(pcap_to_rows(p)[0], pre)
    else:
        print("missing", f, "(skipped)")

#------------------------TRAIN MODEL C (same tuned settings as A and B)-----------------------------
X_C = pd.concat([d['X_train'][colsC], R_train[colsC]], ignore_index=True)
y_C = np.concatenate([d['y_train'].to_numpy(), np.zeros(len(R_train), dtype=int)])
C = clone(A['model'])
C.fit(X_C, y_C)

Xv = pd.concat([d['X_val'][colsC], R_val[colsC]], ignore_index=True)
yv = np.concatenate([d['y_val'].to_numpy(), np.zeros(len(R_val), dtype=int)])
pv = C.predict_proba(Xv)[:, 1]
thr_C = round(float(max(np.arange(0.1, 0.95, 0.05), key=lambda t: f1_score(yv, (pv >= t).astype(int)))), 2)
joblib.dump({'model': C, 'name': 'Random Forest (no environment features)', 'columns': colsC, 'threshold': thr_C},
            os.path.join(HERE, 'best_model_c.joblib'))
models = {'A': (A['model'], A['columns'], A.get('threshold', 0.5)),
          'B': (B['model'], B['columns'], B.get('threshold', 0.5)),
          'C': (C, colsC, thr_C)}

#------------------------COMPARE----------------------------------------------------
def alerts(flag):
    return pd.Series(flag.astype(int)).rolling(ALERT_N, min_periods=1).sum().to_numpy() >= ALERT_K

sandbox, single, alert = {}, {}, {}
for name, (m, cols, t) in models.items():
    ps = m.predict_proba(d['X_val'][cols])[:, 1]
    sandbox[name] = {'threshold': t, 'recall': recall_score(d['y_val'], ps >= t), 'F1': f1_score(d['y_val'], ps >= t)}
    single[name], alert[name] = {}, {}
    for cap, X in captures.items():
        flag = m.predict_proba(X[cols])[:, 1] >= t
        single[name][cap], alert[name][cap] = flag.mean() * 100, alerts(flag).mean() * 100

print("\n---SANDBOX VALIDATION ---")
print(pd.DataFrame(sandbox).T.round(4).to_string())
print("\n--- SINGLE WINDOWS: % of windows flagged (benign rows: lower is better, MALWARE row: higher is better) ---")
print(pd.DataFrame(single).T.round(1).to_string())
print(f"\n--- ALERTS: % of windows inside an alert (at least {ALERT_K} of the last {ALERT_N} flagged) ---")
print(pd.DataFrame(alert).T.round(1).to_string())
print("\nThresholds:", {k: v[2] for k, v in models.items()})
print("The malware capture also holds normal background traffic, so its percentage is a rough detection rate.")
print("Saved best_model_c.joblib")