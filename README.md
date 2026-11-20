# Network Malware Scanner

**CECS 451 Artificial Intelligence, Term Project, Team 21**

An AI-powered tool that analyzes network traffic and flags activity that resembles malware behavior.

---

## Table of Contents

1. [Overview](#1-overview)
2. [The Problem and Our Solution](#2-the-problem-and-our-solution)
3. [How the AI Works](#3-how-the-ai-works)
4. [Running the Demo](#4-running-the-demo)
5. [Using the Application](#5-using-the-application)
6. [Model Performance](#6-model-performance)
7. [System Architecture](#7-system-architecture)
8. [Repository Contents](#8-repository-contents)
9. [Retraining the Models](#9-retraining-the-models)
10. [Scope and Limitations](#10-scope-and-limitations)
11. [Responsible Use](#11-responsible-use)

---

## 1. Overview

Network Malware Scanner is a prototype that scores network traffic for malicious behavior. A machine learning model reads short windows of network traffic (10 packets each) and assigns every window a probability of being malicious. The web application presents the result as a speed-test style scan: the user chooses how much traffic to analyze, presses **SCAN**, and receives a summary, a ranked list of the most suspicious windows, the features the model relies on, and a downloadable CSV report. Earlier scans are kept in a History tab.

**What this prototype demonstrates:** an end-to-end AI pipeline, from data preparation and model selection to a working web interface, applied to malware detection.

**Demo data:** the web application replays a stored sample of labeled traffic windows recorded in a malware sandbox. It does not capture or analyze live traffic from the computer it runs on.

---

## 2. The Problem and Our Solution

### The problem

Malware that reaches a network device usually has to communicate: it scans for other devices, spreads, and contacts remote servers. This activity leaves a pattern in network traffic even when the malicious file itself is hidden. Internet-connected (IoT) devices are especially exposed, because they often have limited built-in security and are rarely monitored by their owners.

### Our solution

We apply machine learning to the traffic itself. Instead of matching traffic against a fixed list of known attack signatures, the model learns what malicious traffic looks like from labeled examples, such as unusual connection-request patterns, packet sizes and timing. This lets it score traffic it has not seen before, as long as the behavior resembles what it learned.

### Who it is for

- Small networks and home users who want a simple way to check whether traffic looks suspicious
- Students and analysts who want to see how an AI-based detector scores traffic and why

### How it compares with existing approaches

| Approach | Example | How it detects | Where our tool fits |
|---|---|---|---|
| Signature-based intrusion detection | Snort | Matches traffic against rules for known attacks | Our model learns patterns from data, so it is not limited to hand-written rules |
| Commercial AI network defense | Darktrace | Learns a network's normal behavior and flags deviations | Our tool is a small, transparent prototype: one open model, visible scores and visible important features |

Our prototype is not a replacement for these systems. It is a focused demonstration of the machine learning method behind AI-based traffic analysis.

---

## 3. How the AI Works

```
Traffic windows  ->  Features  ->  Impute + scale  ->  Random Forest  ->  Malware probability  ->  Verdict
 (10 packets)        (36 values)                                                                (flag if >= threshold)
```

**Data.** We use the CIC-YNU-IoTMal dataset from the Canadian Institute for Cybersecurity: processed network traffic captured while malware ran in a sandbox, plus benign traffic. Each row describes one window of 10 packets.

**Features (36).** Header length, time to live, packet rate, TCP flag fields and counts, protocol fractions (HTTP, HTTPS, DNS, TCP, UDP, ARP, ICMP and others), packet size statistics (minimum, maximum, average, standard deviation), inter-arrival time, and the dominant protocol type (one-hot encoded).

**Method.**
1. Clean the data: remove unknown labels, duplicates and columns that are constant or exact copies of other columns.
2. Split by malware sample (not by row), so a sample never appears in both training and test data. This prevents the model from being scored on traffic it effectively memorized.
3. Fill missing values with the training median and standardize the features, using statistics from the training set only.
4. Train three models (Logistic Regression, Decision Tree, Random Forest), tune each with grouped cross-validation, and compare them on a validation set.
5. Choose the Random Forest, select a decision threshold (0.2) on the validation set to favor catching malware, and score the held-out test set exactly once.

**Output.** Each window receives a score from 0 to 100. Windows at or above the threshold are flagged as malware and labeled Low, Medium or High severity by score.

---

## 4. Running the Demo

The demo needs no training, no dataset download and no internet connection after installation. It takes about five minutes.

### Requirements

- Python 3.11 or newer
- This repository, with `best_model.joblib`, `demo_samples.csv` and `requirements.txt` in the top folder (next to this README)

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

### Start the application

```
python ui/backend/app.py
```

The terminal should print `Model: {'name': 'Random Forest', 'threshold': 0.2}` and `Running on http://127.0.0.1:5000`. Leave it running.

### Open it

Go to **http://127.0.0.1:5000** in a web browser. Press `Ctrl+C` in the terminal to stop the application.

### Troubleshooting

| Problem | Fix |
|---|---|
| Port 5000 is already in use, or the page does not load (common on macOS, where AirPlay Receiver uses port 5000) | Turn off AirPlay Receiver in System Settings > General > AirDrop & Handoff, or change the last line of `ui/backend/app.py` to `app.run(port=5001, debug=False)` and open `http://127.0.0.1:5001` |
| `FileNotFoundError` for `best_model.joblib` or `demo_samples.csv` | Both files must be in the repository's top folder. To keep them elsewhere, set the `MODEL_DIR` environment variable to that folder |
| `ModuleNotFoundError` (flask, pandas, sklearn) | Activate the virtual environment and run `pip install -r requirements.txt` again |
| Import errors from NumPy or pandas | Create a fresh virtual environment and reinstall |
| `InconsistentVersionWarning` from scikit-learn | Harmless. `requirements.txt` pins `scikit-learn==1.8.0`, the version the model was saved with, which avoids it |
| "Scan failed. Is the backend running?" | The terminal running `app.py` was closed. Start it again |

---

## 5. Using the Application

1. On the **Scan** tab, use the slider to choose how many traffic windows to analyze (100 to 2,000).
2. Press **SCAN**. A progress ring runs for a few seconds, then the results appear.
3. Review the results:
   - **Summary cards:** windows scanned, windows flagged, status (`Threats found` or `Clean`) and model scoring time. Because the demo windows carry true labels, three extra cards also show accuracy, missed malware and false alarms (marked "demo only").
   - **Top 10 highest-scoring windows:** score, verdict, severity and true label.
   - **Most important features:** the inputs the Random Forest relies on most.
   - **Model performance (final test set):** the held-out test results from Section 6.
   - **Download CSV:** saves every scored window as `scan_report.csv`.
4. Open the **History** tab to see previous scans (stored in a local SQLite database). **Clear history** removes them.

**What to expect.** The stored sample contains equal numbers of benign and malware windows, and each scan draws a random subset. A scan of 1,000 windows therefore flags a little over half of them, with accuracy around 97% to 98%. In one test run on 1,000 windows: 522 flagged, 3 missed, 20 false alarms, 97.7% accuracy. Exact numbers vary slightly between scans.

---

## 6. Model Performance

### Model comparison (validation set, threshold 0.5)

| Model | Recall | Precision | F1 | ROC AUC | Missed | False alarms |
|---|---|---|---|---|---|---|
| Logistic Regression (baseline) | 0.9628 | 0.9986 | 0.9804 | 0.9962 | 1269 | 45 |
| Logistic Regression (tuned) | 0.9630 | 0.9986 | 0.9805 | 0.9964 | 1263 | 46 |
| Decision Tree (baseline) | 0.9865 | 0.9883 | 0.9874 | 0.9692 | 460 | 398 |
| Decision Tree (tuned) | 0.9799 | 0.9962 | 0.9880 | 0.9906 | 686 | 129 |
| Random Forest (baseline) | 0.9868 | 0.9926 | 0.9897 | 0.9969 | 449 | 252 |
| **Random Forest (tuned)** | 0.9812 | 0.9973 | 0.9892 | 0.9980 | 642 | 90 |

Tuning changed F1 very little. Its main effect was reducing false alarms (252 to 90) at the cost of more missed windows. We selected the tuned Random Forest because it has the highest ROC AUC and the fewest false alarms among the strongest models, then lowered the decision threshold to 0.2 on the validation set to recover malware that would otherwise be missed.

### Final test set (tuned Random Forest, threshold 0.2, scored once)

| Recall | Precision | F1 | ROC AUC | Missed | False alarms |
|---|---|---|---|---|---|
| 0.9897 | 0.9891 | 0.9894 | 0.9982 | 350 | 372 |

### Validation checks

- **Protocol shortcut check.** The first decision tree relied heavily on the TCP feature, which raised the concern that the model only learns "TCP traffic means malware". Removing TCP changed nothing (F1 stayed at 0.9897), and removing all protocol columns lowered F1 by only 0.0009. The model's accuracy does not depend on a single protocol column. Because SYN flags and header length still reveal TCP, this shows robustness to the column, not proof that the model ignores protocol entirely.
- **Per-family check.** Recall was between 98.6% and 100% for every malware family in the validation set, so the high overall score is not driven by one dominant family (Mirai is about 70% of the malware).

These results measure how well the model separates benign from malicious traffic in this dataset. They are not a prediction of performance on every other network (see Section 10).

---

## 7. System Architecture

```
Browser (ui/frontend)  <-- HTTP / JSON -->  Flask server (ui/backend/app.py)
                                                |-- model_service.py : loads the model, scores windows
                                                |-- data_source.py   : supplies windows (demo_samples.csv)
                                                `-- db.py            : SQLite scan history
```

| Endpoint | Purpose |
|---|---|
| `POST /api/scan` | Body `{"records": N}` with N from 100 to 2000. Scores N windows and returns the report |
| `GET /api/history` | Returns previous scans |
| `DELETE /api/history` | Clears scan history |

The data source is isolated in one function (`get_records()` in `data_source.py`), so replacing the stored demo windows with windows built from captured traffic does not require changing the model service or the interface.

---

## 8. Repository Contents

| Path | Purpose |
|---|---|
| `ui/frontend/` | Web interface: `index.html`, `css/`, `js/` |
| `ui/backend/app.py` | Flask server and API |
| `ui/backend/model_service.py` | Loads the model, scores windows, builds the report |
| `ui/backend/data_source.py` | Supplies the windows to scan |
| `ui/backend/db.py` | SQLite scan history |
| `best_model.joblib` | Trained Random Forest and its decision threshold |
| `demo_samples.csv` | 2,000 stored sandbox windows (1,000 benign, 1,000 malware) with true labels |
| `preprocess.joblib` | Imputer, scaler and column order used in training |
| `pipeline_models.py` | Data preparation, split and baseline models |
| `tuning_models.py` | Hyperparameter tuning and threshold sweep |
| `final_test.py` | One-time test-set scoring |
| `train_realworld.py`, `compare_models.py` | Experiments adding real benign traffic (Models B and C) |
| `WS_pcap.py`, `scan_pcap.py` | Convert a raw PCAP to model features and score it from the command line |
| `tuning_results.csv` | Baseline versus tuned validation scores |
| `requirements.txt` | Python dependencies |

---

## 9. Retraining the Models

Not needed for the demo. Retraining requires `pcap.parquet` from the CIC-YNU-IoTMal dataset placed in the top folder.

| Step | Command | Result |
|---|---|---|
| 1 | `python pipeline_models.py` | Prepares the data, saves `splits.joblib` and `preprocess.joblib` |
| 2 | `python tuning_models.py` | Tunes the models, saves `best_model.joblib` and `tuning_results.csv` (slow; set `CHOOSE_K_ONLY = True` to print only the fold-count table first) |
| 3 | `python final_test.py` | Scores the test set once and saves the threshold into the model file |
| 4 | `python train_realworld.py real_benign.pcap` | Optional experiment: Model B, adds real benign traffic from your own capture |
| 5 | `python compare_models.py` | Optional experiment: Model C, drops device-dependent features, and compares all models |

Models B and C are experiments on how the model behaves with real benign traffic. The demo application uses the main model (Model A).

---

## 10. Scope and Limitations

We state these plainly so the results are read in the right context.

- **Demo data.** The application replays stored sandbox traffic. It does not monitor the machine or network it runs on.
- **Malware coverage.** The malware examples are IoT malware from sandbox runs, mostly Mirai. The model has not been validated on other malware families or on enterprise attacks such as ransomware.
- **Benign coverage.** Benign training data is mostly IoT background traffic. Traffic from a different network may look different, and false alarms on unfamiliar traffic are the main risk.
- **Balanced demo sample.** The demo sample is half malware. Real networks are almost entirely benign, so the share of windows flagged in the demo does not carry over.
- **Feature definitions.** The dataset does not document how its features are computed. When features are built from a raw PCAP, a few (rate, inter-arrival time, LLC) are our estimates.
- **One window is weak evidence.** A window contains only 10 packets.
- **Decision support only.** A flag is a prompt to investigate, not proof of infection, and a clean result is not proof of safety.
- **No authentication.** Run the application on your own computer only.

---

## 11. Responsible Use

- Capture and analyze traffic only on networks you own or have permission to monitor.
- Packet captures can contain private information. Do not commit them to the repository (they are excluded in `.gitignore`).
- The application stores only per-scan summaries (counts, duration, status), not packet contents.
- Do not store passwords or API keys in the repository.
