# Network Malware Scanner UI

Speed-test style web UI for the trained model.

- `frontend/` static page (HTML/CSS/JS, no build step)
- `backend/` Flask API: loads `best_model.joblib` and `splits.joblib`, scores records, stores scan history in SQLite

## Run
1. From the repo root, generate the model files if you don't have them:
   `python cecs451proj.py`, then `python tunning.py`, then `python step9.py`
   (they create `splits.joblib` and `best_model.joblib`).
2. `pip install -r ui/requirements.txt`
3. `python ui/backend/app.py`
4. Open http://localhost:5000

Set `MODEL_DIR` to point at a different folder holding the two .joblib files.
