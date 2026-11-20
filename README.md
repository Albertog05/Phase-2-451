# Network Malware Scanner

CECS 451 Artificial Intelligence, Term Project, Team 21

Repository: https://github.com/Albertog05/Phase-2-451

A machine learning tool that scores network traffic for malware-like behavior. A Random Forest reads windows of 10 packets and gives each window a probability of being malicious. A web app lets you run a scan, see a summary and the highest scoring windows, download a CSV report, and review earlier scans.

> **Mock UI, real model.** The web app is a mock in one specific way: it replays stored traffic windows instead of capturing live traffic. Everything the model produces is real. The scores, flags, severity labels, feature importances and the performance numbers come from the trained model and the evaluation scripts in this repository. [What is mock and what is real](#2-what-is-mock-and-what-is-real) lists each piece.

## Contents

1. [Overview](#1-overview)
2. [What is mock and what is real](#2-what-is-mock-and-what-is-real)
3. [Datasets, download steps and terms](#3-datasets-download-steps-and-terms)
4. [Install, configure and run the demo](#4-install-configure-and-run-the-demo)
5. [Reproduce a sample result](#5-reproduce-a-sample-result)
6. [Architecture](#6-architecture)
7. [Data pipeline and models](#7-data-pipeline-and-models)
8. [Results](#8-results)
9. [Main files](#9-main-files)
10. [Retraining from scratch](#10-retraining-from-scratch)
11. [Completed and planned work](#11-completed-and-planned-work)
12. [Limitations](#12-limitations)
13. [Responsible use](#13-responsible-use)
14. [Citations](#14-citations)
15. [References](#15-references)

---

## 1. Overview

**Problem.** Malware on a network device has to communicate. It scans for other devices, spreads, and contacts remote servers, and this leaves a pattern in network traffic. Internet-connected (IoT) devices are especially exposed because they are rarely monitored.

**Approach.** Instead of matching traffic against a fixed list of attack signatures (the approach of tools such as Snort), we train a model on labeled examples of benign and malicious traffic. Each example is one window of 10 packets described by 36 numeric features: header length, TTL, packet rate, TCP flag fields and counts, protocol fractions, packet size statistics, inter-arrival time and the dominant protocol type.

**Output.** Each window gets a malware probability. Windows at or above the model's decision threshold are flagged. The app shows how many windows were flagged, the ten highest scoring windows, which features matter most to the model, and a CSV of every scored window.

**What the project covers.** A complete pipeline: data preparation, model comparison, tuning, a one-time held-out test, experiments with real traffic captured in Wireshark, and a working end-to-end web demo.

---

## 2. What is mock and what is real

| Part | Status | Detail |
|---|---|---|
| Traffic shown in a scan | **Mock** | Random windows drawn from `demo_samples.csv`, a stored file of 2,000 labeled windows (1,000 benign, 1,000 malware) from the sandbox dataset, already scaled to the model's input format. The app does not capture or read live traffic. |
| Scan progress ring | **Mock** | The animation lasts a few seconds for a speed-test feel. The model itself scores 100 to 2,000 windows in well under a second. |
| Model, scores and flags | **Real** | `best_model.joblib` is the trained and tuned Random Forest. Every score, flag and severity label comes from its probabilities and the saved threshold (0.2). |
| Important features | **Real** | Read directly from the trained Random Forest. |
| Accuracy, missed malware and false alarms on the results page | **Real** | Computed live per scan by comparing the model's flags with the true labels stored with each window. |
| Model performance panel (final test set) | **Real** | Output of `final_test.py`, copied into `ui/frontend/js/config.js` as `FINAL_TEST`. |
| CSV download and History tab | **Real** | The CSV is built from the scan result. History is stored in a local SQLite database. |

The official evaluation of the model is the held-out test result in [Section 8](#8-results). The per-scan accuracy in the demo is shown to illustrate the model on stored labeled windows.

---

## 3. Datasets, download steps and terms

### 3.1 Main dataset: CIC-YNU-IoTMal 2026 (sandbox dataset)

Provider: Canadian Institute for Cybersecurity (University of New Brunswick) with Yokohama National University. The dataset page describes the file we use as processed network traffic captured during malware execution, stored as a parquet file. The malware was run in a sandbox, which is why we call this the *sandbox dataset*. It contains benign traffic and several IoT malware families, about 70% of the malware rows being Mirai.

**Download steps** (only needed for retraining, not for the demo):

1. Open https://cicresearch.ca/CICDataset/Yokohama/
2. Open the **X86** folder.
3. Download `pcap.parquet`.
4. Place `pcap.parquet` in the top folder of this repository (it is in `.gitignore` and is not committed).

**License and terms.** The dataset page does not state a license and does not describe an access request or approval process. Please see the dataset page for terms. The page shows copyright to the University of New Brunswick. We use the data for coursework only and do not redistribute it. `demo_samples.csv` contains 2,000 rows of scaled numeric features and labels, with no packet contents.

The authors also publish their sandbox code: https://github.com/UNBCIC/CIC-YNU-IoTMal-Sandbox

### 3.2 Mirai test capture: IoT-23

Provider: Stratosphere Laboratory (Aposemat IoT-23). Our test file is from capture `CTU-IoT-Malware-Capture-34-1`, a Mirai infection, saved locally as `mirai_test.pcap`. It was used only to test the models on traffic from outside the training dataset.

- Dataset page: https://www.stratosphereips.org/datasets-iot23
- Zenodo record: http://doi.org/10.5281/zenodo.4743746

License: the Zenodo record (https://zenodo.org/record/4743745) lists IoT-23 under Creative Commons Attribution 4.0 International (CC BY 4.0), which requires attribution. The citation is in [Section 14](#14-citations). The Stratosphere dataset page itself does not state a license. The capture file is not committed to this repository.

### 3.3 Our own benign captures

We recorded benign traffic ourselves with Wireshark on a network and device we own. See [Section 10](#10-retraining-from-scratch) for how captures are turned into model input. These files can contain private information (addresses, DNS names), so they are never committed.

---

## 4. Install, configure and run the demo

The demo needs no training, no dataset download and no internet connection after installation. It takes about five minutes.

### Requirements

- Python 3.11 or newer
- These files in the **top folder** of the repository: `best_model.joblib`, `demo_samples.csv`, `requirements.txt`

### Install

Open a terminal in the top folder of the repository.

macOS or Linux:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` pins exact versions. scikit-learn is pinned to 1.8.0 because that is the version the model file was saved with.

### Configure

No configuration is required, and the app uses no passwords or API keys. One optional setting exists:

| Variable | Purpose | Default |
|---|---|---|
| `MODEL_DIR` | Folder that contains `best_model.joblib` and `demo_samples.csv` | The top folder of the repository |

The slider limits (100 to 2,000 windows) are set in `ui/frontend/js/config.js` and in `ui/backend/app.py`. The two must match, and 2,000 is the number of windows stored in `demo_samples.csv`.

### Run

From the top folder:

```
python ui/backend/app.py
```

The terminal prints `Model: {'name': 'Random Forest', 'threshold': 0.2}` and `Running on http://127.0.0.1:5000`. Leave it running and open **http://127.0.0.1:5000** in a browser. Press `Ctrl+C` in the terminal to stop.

### Use

1. On the **Scan** tab, set the number of traffic windows with the slider (100 to 2,000).
2. Press **SCAN**. The ring animates, then the results appear.
3. Read the results: summary cards (windows scanned, flagged, status, model time, and the demo-only accuracy, missed malware and false alarms), the top 10 windows with score, verdict, severity and true label, the most important features, and the final test set performance.
4. **Download CSV** saves every scored window as `scan_report.csv`.
5. The **History** tab lists earlier scans. **Clear history** removes them.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 is in use, or the page does not load (common on macOS, where AirPlay Receiver uses port 5000) | Turn off AirPlay Receiver in System Settings > General > AirDrop & Handoff, or change the last line of `ui/backend/app.py` to `app.run(port=5001, debug=False)` and open `http://127.0.0.1:5001` |
| `FileNotFoundError` for `best_model.joblib` or `demo_samples.csv` | Both files must be in the top folder, or in the folder named by `MODEL_DIR` |
| `ModuleNotFoundError` | Activate the virtual environment and run `pip install -r requirements.txt` again |
| NumPy or pandas import errors | Create a fresh virtual environment and reinstall |
| `InconsistentVersionWarning` from scikit-learn | The installed scikit-learn is not 1.8.0. Reinstall with `requirements.txt` |
| "Scan failed. Is the backend running?" | The terminal running `app.py` was closed. Start it again |
| Want an empty History | Press **Clear history**, or stop the app and delete `ui/backend/scans.db` (it is recreated on start) |

---

## 5. Reproduce a sample result

1. Start the app as in Section 4 and open it in a browser.
2. Set the slider to 1,000 windows and press **SCAN**.
3. You should see roughly half of the windows flagged and an accuracy between about 96% and 98%, with only a handful of missed windows and a few dozen false alarms at most. One run on our machine: 1,000 windows, 522 flagged, 3 missed, 20 false alarms, 97.7% accuracy.

Exact numbers change on every scan because each scan draws a random subset. The stored sample is half malware, so about half of the windows being flagged is correct behavior here and does not describe a real network, where almost all traffic is benign.

The scan endpoint can also be called directly:

```
curl -X POST -H "Content-Type: application/json" -d '{"records": 500}' http://127.0.0.1:5000/api/scan
```

---

## 6. Architecture

```
Browser (ui/frontend)  <-- HTTP, JSON -->  Flask server (ui/backend/app.py)
                                              |-- data_source.py   : supplies windows (demo_samples.csv)
                                              |-- model_service.py : loads best_model.joblib, scores windows
                                              `-- db.py            : SQLite scan history (scans.db)
```

| Endpoint | Purpose |
|---|---|
| `POST /api/scan` | Body `{"records": N}`, N from 100 to 2,000. Scores N windows and returns the report. Other values return an error |
| `GET /api/history` | Returns earlier scans |
| `DELETE /api/history` | Clears the history |

The source of windows is isolated in one function, `get_records()` in `data_source.py`. Moving from stored windows to windows built from captured traffic means replacing that function. The model service and the interface stay as they are.

Front end: plain HTML, CSS and JavaScript with no build step. `config.js` holds the settings, `api.js` the server calls, `slider.js` and `scan.js` the controls, `results.js` the results view and CSV export, `history.js` and `router.js` the History tab.

---

## 7. Data pipeline and models

The pipeline follows the standard steps from our machine learning course (CECS 456).

1. **Clean.** Remove rows with unknown labels and duplicates. Replace infinite values with missing values. Drop columns that are constant (Arch, SMTP, IRC) or exact copies or functions of other columns (Tot size, Variance, Tot sum, Number).
2. **Select features and target.** 36 features after encoding. Target: malicious (1) or benign (0).
3. **Encode.** The protocol type is a code, not a quantity, so it is one-hot encoded.
4. **Split by malware sample.** Stratified group k-fold on the sample hash (10 folds: 8 train, 1 validation, 1 test). A sample never appears in more than one split, so the test score reflects unseen malware samples.
5. **Impute and scale.** Median imputation and standardization, fitted on the training set only.
6. **Compare models.** Logistic Regression, Decision Tree and Random Forest, each with a baseline and a tuned version.
7. **Tune.** Grid search (Logistic Regression, Decision Tree) and randomized search (Random Forest) with grouped cross-validation, on a 100,000 row subsample. The winners are refit on the full training set.
8. **Choose a threshold.** A threshold sweep on the validation set. We use 0.2 so fewer malware windows are missed.
9. **Final test.** The test set is scored once, by `final_test.py`, after all choices are made.

### Models used in this project

| Model | File | Training data | Features | Role |
|---|---|---|---|---|
| A | `best_model.joblib` | Sandbox dataset | 36 | **Used by the demo app** |
| B | `best_model_realworld.joblib` | Sandbox dataset plus our real benign captures | 36 | Experiment on real traffic |
| C | `best_model_c.joblib` | Same as B | 33 (no TTL, Rate, IAT) | Experiment on real traffic |

After cleaning, the dataset has 424,033 windows. No large language model or external API is used anywhere in the project. All three models below use the same tuned Random Forest settings. Model C leaves out TTL, Rate and IAT because they depend on the capturing device or are estimated when features are computed from a raw capture.

---

## 8. Results

### Model comparison (validation set, threshold 0.5)

| Model | Recall | Precision | F1 | ROC AUC | Missed | False alarms |
|---|---|---|---|---|---|---|
| Logistic Regression (baseline) | 0.9628 | 0.9986 | 0.9804 | 0.9962 | 1269 | 45 |
| Logistic Regression (tuned) | 0.9630 | 0.9986 | 0.9805 | 0.9964 | 1263 | 46 |
| Decision Tree (baseline) | 0.9865 | 0.9883 | 0.9874 | 0.9692 | 460 | 398 |
| Decision Tree (tuned) | 0.9799 | 0.9962 | 0.9880 | 0.9906 | 686 | 129 |
| Random Forest (baseline) | 0.9868 | 0.9926 | 0.9897 | 0.9969 | 449 | 252 |
| **Random Forest (tuned)** | 0.9812 | 0.9973 | 0.9892 | 0.9980 | 642 | 90 |

Tuning changed F1 very little. Its main effect was fewer false alarms (252 to 90) at the cost of more missed windows. The tuned Random Forest has the highest ROC AUC, and lowering its threshold to 0.2 on the validation set recovers some of the missed malware.

### Final test set (tuned Random Forest, threshold 0.2, scored once)

| Recall | Precision | F1 | ROC AUC | Missed | False alarms |
|---|---|---|---|---|---|
| 0.9897 | 0.9891 | 0.9894 | 0.9982 | 350 | 372 |

### Checks on why the scores are so high

- **Is the model only learning "TCP means malware"?** Removing the TCP column changed nothing (F1 stayed at 0.9897). Removing all 17 protocol columns lowered F1 by only 0.0009. The decision tree's high TCP importance came from correlated features (SYN count, SYN flag number, header length) sharing one signal. Those features still reveal TCP, so this shows the score does not depend on one column, not that protocol is ignored.
- **Does it only catch Mirai?** Recall was between 98.6% and 100% for every malware family in the validation set, even though Mirai is about 70% of the malware.

### Real traffic captured with Wireshark

Sandbox scores are very high, so we tested the models on traffic from outside the dataset. On the Mirai capture from IoT-23, **Model B flagged 41.6% of the windows and Model C flagged 37.7%**. That capture also contains normal background traffic, so these percentages are a rough detection rate and not a measured recall.

This is far below the sandbox results. The likely reason is that the dataset's benign and malware traffic differ from traffic on other networks and in other captures, so the sandbox scores should not be read as real-world performance. Adding our own benign captures (Models B and C) was our attempt to narrow that gap. Model C, without the device-dependent features, was slightly worse than Model B on this capture.

We also tried an alert rule (alert when at least 5 of the last 10 windows are flagged). It did not improve results in our test, so it is not part of the app.

---

## 9. Main files

| Path | Purpose |
|---|---|
| `ui/backend/app.py` | Flask server and API |
| `ui/backend/model_service.py` | Loads the model, scores windows, builds the report |
| `ui/backend/data_source.py` | Supplies the windows to scan |
| `ui/backend/db.py` | SQLite scan history |
| `ui/frontend/` | Web interface (`index.html`, `css/`, `js/`) |
| `best_model.joblib` | Model A and its threshold, used by the app |
| `demo_samples.csv` | 2,000 stored labeled windows for the demo |
| `preprocess.joblib` | Imputer, scaler and column order from training |
| `pipeline_models.py` | Data preparation, split, baseline models, protocol checks |
| `tuning_models.py` | Hyperparameter search and threshold sweep |
| `final_test.py` | One-time test set scoring |
| `WS_pcap.py` | Turns a raw Wireshark capture into the same window features as the dataset |
| `scan_pcap.py` | Scores one capture from the command line |
| `train_realworld.py` | Builds Model B from a benign capture |
| `compare_models.py` | Builds Model C and compares A, B and C on all captures |
| `tuning_results.csv` | Baseline versus tuned validation scores |
| `requirements.txt` | Pinned packages for the demo |
| `requirements-training.txt` | Demo packages plus `pyarrow` and `dpkt` for retraining and captures |

---

## 10. Retraining from scratch

Not needed for the demo. Install `requirements-training.txt` instead of `requirements.txt`, and download `pcap.parquet` as described in Section 3.1.

| Step | Command | Result |
|---|---|---|
| 1 | `python pipeline_models.py` | Prepares the data, saves `splits.joblib` and `preprocess.joblib` |
| 2 | `python tuning_models.py` | Tunes the models, saves `best_model.joblib` and `tuning_results.csv`. This is slow. Set `CHOOSE_K_ONLY = True` first to print only the fold-count table |
| 3 | `python final_test.py` | Scores the test set once and saves the threshold into the model file. Run it once only |
| 4 | `python train_realworld.py real_benign.pcap` | Optional. Builds Model B from your own benign capture |
| 5 | `python compare_models.py` | Optional. Builds Model C and compares A, B and C. Uses `real_benign.pcap`, and `second_session.pcap` and `mirai_test.pcap` if present |

### Working with Wireshark captures

1. Capture on a network you own, with Wireshark or `tcpdump`, and save as `.pcap` or `.pcapng` with an Ethernet link type.
2. `WS_pcap.py` cuts the capture into windows of 10 packets and computes the same features as the dataset. The dataset does not publish its feature definitions, so we decoded most of them from the dataset rows (header length, TTL, TCP flags, protocol fractions, packet size statistics, and variance). Rate, IAT and LLC are our estimates (Rate is one divided by the mean gap between packets, LLC is the share of IP packets). This is one reason real captures behave differently from the dataset.
3. `scan_pcap.py capture.pcap [model_file]` scores a capture and prints the share of windows flagged, how much of that is TCP traffic, and which features sit furthest from the training data.

---

## 11. Completed and planned work

**Completed**
- Data cleaning, feature selection, grouped train, validation and test split
- Three models compared, tuned and tested once on held-out data
- Checks on protocol dependence and per-family recall
- Model B and Model C experiments with real benign captures, tested on an IoT-23 Mirai capture
- Capture to features converter (`WS_pcap.py`) and command line scanner (`scan_pcap.py`)
- Web demo with scan, results, CSV download and scan history

**Planned**
- Upload a Wireshark capture in the web app and score it there, then live capture (replace `get_records()` in `data_source.py`)
- Collect more varied benign and malware captures to close the gap seen on real traffic
- A leave-one-malware-family-out test, to measure how well the model catches a family it never saw in training
- Confirm the estimated features (Rate, IAT, LLC) against the dataset's own definitions

---

## 12. Limitations

- **Mock traffic source.** The app replays stored sandbox windows. It does not monitor the machine or network it runs on.
- **Sandbox versus real traffic.** Scores on the sandbox dataset are very high. On a real Mirai capture the models flagged only about 38% to 42% of the windows (Section 8). Do not read the sandbox scores as real-world performance.
- **Malware coverage.** The malware is IoT malware from sandbox runs, about 70% Mirai. We have not validated other malware types or enterprise attacks such as ransomware.
- **Benign coverage.** Benign training data is mostly IoT background traffic plus captures from one network and device. Traffic elsewhere may look different, and false alarms are a risk.
- **Balanced demo sample.** The demo sample is half malware, so the share of windows flagged there does not carry over to a real network.
- **Estimated features.** Rate, IAT and LLC are estimates when computed from a raw capture.
- **One window is weak evidence.** A window holds only 10 packets.
- **Decision support only.** A flag is a prompt to investigate. It does not prove infection, and a clean result does not prove safety.
- **No authentication.** Run the app on your own computer only.

---

## 13. Responsible use

- Capture and analyze traffic only on networks you own or have permission to monitor.
- Packet captures can contain private information. They are excluded from the repository in `.gitignore`.
- The app stores only per-scan summaries (counts, duration, status) in `scans.db`, not packet contents. `scans.db` is also in `.gitignore`.
- Only analyze capture files. Do not run malware to produce traffic.
- Do not store passwords or API keys in the repository.

**AI assistance.** Parts of the code and documentation were written with the help of an AI assistant (Claude), which the course allows. The team reviewed and tested the work.

---

## 14. Citations

Dadkhah, S., Okey, O. D., Maret, S. A., Lo, Y.-W., Firouzi, A., Kuki, R., Sasaki, T., Yoshioka, K., Ban, T., Ozawa, S., & Ghorbani, A. A. (2026). CIC-YNU-IoTMal: A comprehensive multilayer dataset for static and dynamic analysis of IoT malware behavior. *Information Systems*, 102722.

Garcia, S., Parmisano, A., & Erquiaga, M. J. (2020). *IoT-23: A labeled dataset with malicious and benign IoT network traffic* (Version 1.0.0) [Data set]. Zenodo. http://doi.org/10.5281/zenodo.4743746

---

## 15. References

Machine learning methods (documentation for the tools used):

- scikit-learn. RandomForestClassifier. https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
- scikit-learn. StratifiedGroupKFold. https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html
- scikit-learn. Tuning the hyper-parameters of an estimator (GridSearchCV, RandomizedSearchCV). https://scikit-learn.org/stable/modules/grid_search.html
- scikit-learn. Imputation of missing values. https://scikit-learn.org/stable/modules/impute.html
- scikit-learn. Preprocessing data (StandardScaler, one-hot encoding). https://scikit-learn.org/stable/modules/preprocessing.html
- scikit-learn. Metrics and scoring (precision, recall, F1, ROC AUC). https://scikit-learn.org/stable/modules/model_evaluation.html

Capturing and reading network traffic:

- Wireshark Foundation. Wireshark User's Guide. https://www.wireshark.org/docs/wsug_html_chunked/
- The Tcpdump Group. tcpdump manual page. https://www.tcpdump.org/manpages/tcpdump.1.html
- dpkt documentation. https://dpkt.readthedocs.io/

Course material: CECS 456 (data pipeline and model tuning steps).
