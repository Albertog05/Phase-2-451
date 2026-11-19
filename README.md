# Malware Traffic Detector

CECS 451 term project, Team 21.

An AI tool that scores network traffic for malware-like behavior. A model looks at windows of 10 packets and gives each window a probability of being malicious. The app shows a ranked list of windows, raises an alert when several nearby windows are flagged, and exports a CSV report.

**Scope, in one paragraph.** The models are trained on IoT malware (mostly Mirai) recorded in a sandbox (CIC-YNU-IoTMal), plus benign traffic. This prototype shows that the method works on that data and can be run on a captured PCAP. It is not validated on other malware families, other networks, or enterprise attacks such as ransomware or credential theft. See [Limitations](#limitations).

## Status

| Part | Status |
|---|---|
| Data pipeline, baseline models, tuning, final test scoring (`cecs451proj.py`, `tunning.py`, `step9.py`) | Done |
| Model A (sandbox only), Model B (adds real benign traffic), Model C (also drops device dependent features) | Done |
| Demo mode in the web app: replays held-out sandbox test data with true labels | Done |
| Real-traffic mode: upload a PCAP, get ranked windows, alerts and a CSV report (`/pcap`) | Done. Checked with the saved models and synthetic captures. Real-capture results: [TEAM: add the table from `evaluate_captures.py`] |
| Generalization checks: `family_holdout.py`, `feature_parity.py`, `evaluate_captures.py` | Scripts done. Results: [TEAM: add after running them] |
| Database layer (`database/`) | Done and tested on its own. Connected to the UI: [TEAM: yes or no] |
| Live capture started from inside the app | **Not implemented.** Capture with Wireshark or tcpdump, then upload the file |

## How it works

```
PCAP  ->  windows of 10 packets  ->  features  ->  impute + scale  ->  model  ->  probability per window
                                                                                   |
                                  flagged if probability >= the model's threshold  v
                                  alert if at least 5 of the last 10 windows are flagged
```

- `pcap_features.py` turns a raw PCAP into the same kind of rows as `pcap.parquet`. The dataset does not publish its feature definitions, so some are decoded from the data and a few are estimated (Rate, IAT, LLC). See Limitations.
- `preprocess.joblib` holds the imputer, the scaler and the column order from training, so live rows are prepared exactly like training rows.
- One flagged window is weak evidence, so the app reports **alerts** (at least 5 of the last 10 windows flagged) next to single flagged windows.

### Models

| Model | File | Training data | Features | Threshold |
|---|---|---|---|---|
| A | `best_model.joblib` | Sandbox data only | 36 | 0.2 (picked on validation, `step9.py`) |
| B | `best_model_realworld.joblib` | Sandbox + real benign traffic | 36 | 0.4 (best F1 on validation) |
| C | `best_model_c.joblib` | Sandbox + real benign traffic | 33 (no TTL, Rate, IAT) | 0.5 (best F1 on validation) |

All three are the same tuned Random Forest settings. Use Model C for real traffic because it depends least on the capturing device and on estimated features. That is a design choice, not a measured result. Compare the models on your own captures with `evaluate_captures.py`.

### Results so far (validation set, threshold 0.5)

| Model | Recall | Precision | F1 | ROC AUC | Missed | False alarms |
|---|---|---|---|---|---|---|
| Logistic Regression (baseline) | 0.9628 | 0.9986 | 0.9804 | 0.9962 | 1269 | 45 |
| Logistic Regression (tuned) | 0.9630 | 0.9986 | 0.9805 | 0.9964 | 1263 | 46 |
| Decision Tree (baseline) | 0.9865 | 0.9883 | 0.9874 | 0.9692 | 460 | 398 |
| Decision Tree (tuned) | 0.9799 | 0.9962 | 0.9880 | 0.9906 | 686 | 129 |
| Random Forest (baseline) | 0.9868 | 0.9926 | 0.9897 | 0.9969 | 449 | 252 |
| **Random Forest (tuned)** | 0.9812 | 0.9973 | 0.9892 | 0.9980 | 642 | 90 |

Tuning changed the F1 score very little (Random Forest 0.9897 to 0.9892). Its main effect was fewer false alarms (252 to 90) at the cost of more missed windows, and the lower threshold chosen in `step9.py` wins some of that recall back. Final test-set scores come from `python step9.py`, which is run once.

These numbers are on sandbox data. They say how well the model separates sandbox benign traffic from sandbox malware, not how it performs on a real network.

## Setup

Python 3.10 or newer.

```
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Quick start (no training)

If the repo contains `preprocess.joblib`, `best_model_c.joblib` and `demo_sample.joblib`, you can skip straight to [Run the app](#run-the-app) and to the sample check below.

### Full pipeline (retrains everything)

1. Download `pcap.parquet` from the CIC-YNU-IoTMal dataset (Canadian Institute for Cybersecurity) and place it in the repo root. [TEAM: add the download URL and the dataset license]
2. Run the scripts in this order. Each one saves files for the next.

| Step | Command | Saves |
|---|---|---|
| 1 | `python cecs451proj.py` | `splits.joblib`, `preprocess.joblib` (also prints the exploration and baseline results) |
| 2 | `python tunning.py` | `best_model.joblib` (Model A), `tuning_results.csv` |
| 3 | `python step9.py` | Prints the test-set scores. **Run once.** Saves the threshold into `best_model.joblib` |
| 4 | `python train_realworld.py real_benign.pcap` | `best_model_realworld.joblib` (Model B). Needs your own benign capture |
| 5 | `python compare_models.py` | `best_model_c.joblib` (Model C) and a comparison of A, B and C. Needs `real_benign.pcap`. `second_session.pcap` and `mirai_test.pcap` are used if present |
| 6 | `python make_demo_sample.py` | `demo_sample.joblib`, a small test sample so the demo runs without `splits.joblib` |

`tunning.py` can take a long time. Set `CHOOSE_K_ONLY = True` at the top to print only the fold-count table first.

### Run the app

```
python ui/backend/app.py
```

[TEAM: confirm this command and the port, then add the address to open.]

- **Demo mode** (main page). Press Scan to score random records from the held-out sandbox test set. These are recorded rows with true labels, so the page can also show missed malware and false alarms. It is real model scoring on replayed data, not a scan of live traffic.
- **Real-traffic mode** (`/pcap`). Upload a `.pcap` or `.pcapng` exported from Wireshark or tcpdump (Ethernet captures), pick a model, and press Scan. You get a status, flagged windows, alert episodes, a timeline, the 100 highest scoring windows with "what stands out", and a link to the full CSV. The file is deleted from the server after scoring. To turn this page on, `app.py` needs these two lines:

```python
from pcap_routes import bp as pcap_bp
app.register_blueprint(pcap_bp)
```

### Reproduce a sample result

This checks that the real-traffic pipeline runs. The captures are **synthetic** (made-up packets), so the result proves the plumbing, not accuracy.

```
python make_sample_pcap.py
python evaluate_captures.py benign:sample_data/synthetic_browsing.pcap malware:sample_data/synthetic_scan.pcap
```

Expected with Models B and C: the browsing-like capture has 0.0% of windows flagged and no alerts. The scan-like capture has 100.0% of windows flagged, 96.7% inside one alert episode.

## Checking how far the results can be trusted

| Question | Script | What it does |
|---|---|---|
| Does it catch a malware family it never saw in training? | `python family_holdout.py` (`--fast` for a quick run) | Leaves one family out of training at a time and measures recall on it. Compares with the recall when the family was in training |
| Does it work on real captures, benign and malware? | `python evaluate_captures.py benign:a.pcap malware:b.pcap` | Prints false alarm rate (benign) and detection rate (malware) for every model, per window and per alert, and saves `capture_eval.csv` |
| Does `pcap_features.py` compute the same numbers as the dataset? | `python feature_parity.py sample.pcap --hash <Hash>` | Extracts features from a raw dataset PCAP and compares them with the `pcap.parquet` rows of the same sample. `--list-hashes` shows values to use |

For the malware check, use a labeled capture that does **not** come from the training dataset. Only analyze capture files. Do not run malware to produce traffic.

## Files

| File | Purpose |
|---|---|
| `cecs451proj.py` | Exploration, cleaning, split, imputation, scaling, baseline models, protocol theories |
| `tunning.py` | Hyperparameter search for the three models, threshold sweep, saves Model A |
| `step9.py` | One-time test-set scoring, saves the threshold |
| `pcap_features.py` | Raw PCAP to window features (10 packets per window) |
| `pcap_scoring.py` | Scores a PCAP with a saved model: flags, alerts, reasons, timeline |
| `scan_pcap.py` | Command line scan of one PCAP, prints diagnostics, saves `real_scan_results.csv` |
| `train_realworld.py` | Builds Model B from a real benign capture (time ordered split) |
| `compare_models.py` | Builds Model C and compares A, B, C on every capture |
| `evaluate_captures.py` | Compares models on any labeled captures |
| `family_holdout.py` | Leave-one-malware-family-out test |
| `feature_parity.py` | Checks the feature definitions against the dataset |
| `make_demo_sample.py`, `make_sample_pcap.py` | Create the small demo sample and the synthetic sample captures |
| `ui/backend/model_service.py`, `data_source.py` | Demo mode: model loading and replayed test records |
| `ui/backend/pcap_routes.py` | Real-traffic mode: upload page and API |
| `ui/` (frontend), `config.js` | Web page and its settings |
| `database/` | SQLite layer: users, models, scans, scored windows (see `database/DATABASE.md`) |

## Limitations

- **Malware coverage.** All malware examples are IoT malware from sandbox runs, about 70% Mirai. How well the model catches other families is measured by `family_holdout.py`. [TEAM: add the result]
- **Benign coverage.** Benign data is the dataset's benign traffic plus captures from one network and device. A different network can look different, and false alarms on real traffic are the main risk.
- **Estimated features.** The dataset does not document its features. Rate, IAT and LLC in `pcap_features.py` are estimates. Model C drops TTL, Rate and IAT but still uses LLC. `feature_parity.py` is how to check this.
- **Weak evidence per window.** A window is 10 packets. That is why alerts need several flagged windows.
- **Explanations are approximate.** "What stands out" lists features that are unusual and important to the model. It is not an exact explanation of one prediction.
- **No live capture in the app.** Real-traffic mode needs a PCAP file. Link types other than Ethernet or raw IP are rejected.
- **No login on the real-traffic page.** Run the app on your own machine only. Do not expose it to a network.
- **Not a security product.** Results are decision support, not proof that a machine is infected or clean.

## Responsible use and privacy

- Only capture and analyze traffic on networks you own or have permission to monitor.
- A PCAP can contain private information (addresses, DNS names, content). Do not commit captures. They are in `.gitignore`.
- The app keeps only per-window feature summaries and scores, not packet contents. Uploaded files are deleted right after scoring.
- Do not put passwords, API keys, or other secrets in the repo. The database file is in `.gitignore` because it holds password hashes and scan results.
