#CECS 451 Phase 2: runs a saved model on a raw PCAP.
#Usage:  python scan_pcap.py real_benign.pcap     (Model A)
#python scan_pcap.py other_day.pcap best_model_realworld.joblib  (Model B)
#Needs best_model.joblib (tuning.py + final_test.py) and preprocess.joblib from pipeline_models.py).

import os
import sys
import joblib
import pandas as pd
from WS_pcap import pcap_to_rows

HERE = os.path.dirname(os.path.abspath(__file__))
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'real_benign.pcap')

df, dropped = pcap_to_rows(path)
print(f"{os.path.basename(path)}: {len(df)} windows of 10 packets ({dropped} leftover packets dropped)")

pre = joblib.load(os.path.join(HERE, 'preprocess.joblib'))
MODEL = sys.argv[2] if len(sys.argv) > 2 else 'best_model.joblib'
b   = joblib.load(os.path.join(HERE, MODEL))
print('Model file:', MODEL)
cols, thr = pre['columns'], b.get('threshold', 0.5)

#same encoding as training: Protocol Type becomes Protocol Type_1, _6, _17 ... then the same column order
dummies = pd.get_dummies(df['Protocol Type'].astype(int), prefix='Protocol Type', dtype=float)
X = pd.concat([df, dummies], axis=1).reindex(columns=cols, fill_value=0.0)
X = pd.DataFrame(pre['imputer'].transform(X), columns=cols)
Z = pd.DataFrame(pre['scaler'].transform(X), columns=cols)

proba = b['model'].predict_proba(Z[b['columns']])[:, 1]
flag  = proba >= thr

print(f"\nFlagged as malware at threshold {thr}: {flag.sum()} of {len(flag)} windows ({flag.mean() * 100:.1f}%)")
print(f"Flagged as malware at threshold 0.5:  {(proba >= 0.5).sum()} of {len(flag)} windows ({(proba >= 0.5).mean() * 100:.1f}%)")
print("(on a benign capture this share is the false alarm rate)")
print("\nMalware probability percentiles:")
print(pd.Series(proba).quantile([0.1, 0.25, 0.5, 0.75, 0.9, 0.99]).round(4).to_string())

tcp = df['TCP'].to_numpy() > 0.5
if tcp.any():
    print(f"\nTCP-heavy windows: {tcp.sum()} | flagged: {(flag & tcp).sum()} ({(flag & tcp).sum() / tcp.sum() * 100:.1f}%)")
if (~tcp).any():
    print(f"Other windows:     {(~tcp).sum()} | flagged: {(flag & ~tcp).sum()} ({(flag & ~tcp).sum() / (~tcp).sum() * 100:.1f}%)")

#check: Rate and IAT are the two guessed features. Set both to the training average and score again
Z2 = Z.copy()
Z2['Rate'] = 0.0
Z2['IAT']  = 0.0
p2 = b['model'].predict_proba(Z2[b['columns']])[:, 1]
print(f"\nSame scan with Rate and IAT neutralized: flagged at {thr}: {(p2 >= thr).mean() * 100:.1f}% | at 0.5: {(p2 >= 0.5).mean() * 100:.1f}%")
if tcp.any():
    print(f"TCP-heavy windows flagged at 0.5: {((proba >= 0.5) & tcp).sum()} of {tcp.sum()}")

#how far is this traffic from the training data? average z-score per feature (3+ means very different; median so a few extreme windows don't dominate)
z = ((X.median() - pre['scaler'].mean_) / pre['scaler'].scale_).round(2)
print("\nFeatures furthest from the training data (z-score of the median):")
print(z.reindex(z.abs().sort_values(ascending=False).index).head(8).to_string())

out = df.copy()
out['malware probability'] = proba
out['verdict'] = ['MALWARE' if f else 'Benign' for f in flag]
out.to_csv(os.path.join(HERE, 'real_scan_results.csv'), index=False)
print("\nSaved real_scan_results.csv") #this is just for our own testing measures not commited