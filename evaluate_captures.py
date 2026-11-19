#evaluate_captures.py
#Omar Juarez
#CECS 451 Phase 2: scores any number of PCAPs with Models A, B and C and prints one comparison table.
#Use it for the live-test evidence: false alarms on benign captures, detection on malware captures.
#
#Usage:  python evaluate_captures.py benign:real_benign.pcap benign:second_session.pcap malware:some_malware.pcap
#        python evaluate_captures.py benign:day2.pcap --models B,C --out my_results.csv
#        label is benign, malware or left out (unknown). Only the models whose files exist are used.
#Needs: preprocess.joblib and the model files in this folder, pcap_features.py, pcap_scoring.py, dpkt.
#
#How to read it
#  benign capture : flagged % is the false alarm rate. Lower is better. Alert episodes per hour is the number that
#                   decides whether a real user would be annoyed. Short captures (under a minute) have no per-hour rate.
#  malware capture: flagged % is a rough detection rate. Captures usually also hold normal background traffic, so even a
#                   perfect model will not reach 100%. Use captures that do NOT come from the training dataset.
import argparse
import os
import warnings

import pandas as pd

import pcap_scoring as ps

warnings.filterwarnings('ignore')
HERE = os.path.dirname(os.path.abspath(__file__))
LABELS = ('benign', 'malware')

parser = argparse.ArgumentParser(description='Compare models A, B and C on labeled captures')
parser.add_argument('captures', nargs='+', help='label:path (label = benign or malware), or just a path')
parser.add_argument('--models', default='', help='comma separated model keys, for example B,C (default: all that exist)')
parser.add_argument('--alert-n', type=int, default=ps.ALERT_N)
parser.add_argument('--alert-k', type=int, default=ps.ALERT_K)
parser.add_argument('--out', default=os.path.join(HERE, 'capture_eval.csv'))
args = parser.parse_args()

pre = ps.load_preprocess(HERE)
bundles = ps.load_bundles(HERE)
if args.models:
    wanted = [m.strip().upper() for m in args.models.split(',')]
    bundles = {k: v for k, v in bundles.items() if k in wanted}
if not bundles:
    raise SystemExit('No model files found next to this script (best_model*.joblib).')

rows = []
for item in args.captures:
    label, _, rest = item.partition(':')
    if label.lower() in LABELS and rest:
        label, path = label.lower(), rest
    else:
        label, path = 'unknown', item   #no label, or a path that itself contains a colon
    if not os.path.exists(path):
        print('missing file, skipped:', path)
        continue
    for key, b in bundles.items():
        s, _, _ = ps.score_capture(path, b, pre, args.alert_n, args.alert_k)
        rows.append({'capture': os.path.basename(path), 'expected': label, 'model': key, 'threshold': s['threshold'],
                     'windows': s['windows'], 'flagged_%': s['flagged_pct'], 'in_alert_%': s['alert_pct'],
                     'alert_episodes': s['alert_episodes'], 'minutes': round(s['capture_seconds'] / 60, 1),
                     'episodes_per_hour': s['alerts_per_hour']})

if not rows:
    raise SystemExit('Nothing was scored.')
table = pd.DataFrame(rows)
table.to_csv(args.out, index=False)

print(f"\nAlert rule: at least {args.alert_k} of the last {args.alert_n} windows flagged (a window = 10 packets)")
for label, name in [('benign', 'BENIGN captures: flagged % = false alarm rate (lower is better)'),
                    ('malware', 'MALWARE captures: flagged % = rough detection rate (higher is better)'),
                    ('unknown', 'UNLABELED captures')]:
    part = table[table['expected'] == label].drop(columns='expected')
    if len(part):
        print(f'\n--- {name} ---')
        print(part.sort_values(['capture', 'model']).to_string(index=False))
print(f'\nSaved {args.out}')
