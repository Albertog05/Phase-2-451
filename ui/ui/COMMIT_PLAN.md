# 9-day commit plan (paths are inside ui/)

| Day | Files | Commit message |
|-----|-------|----------------|
| 1 | README.md, .gitignore, requirements.txt, frontend/js/config.js (+ paste STRUCTURE_SNIPPET.txt into the repo's Structure file) | Set up UI folder, config, and docs |
| 2 | backend/data_source.py, backend/model_service.py | Load model and score test-set records |
| 3 | backend/db.py | Add SQLite scan history |
| 4 | backend/app.py | Add Flask API (/api/scan, /api/history) |
| 5 | frontend/index.html, css/base.css, js/router.js, js/main.js | Add page layout, header, and tab routing |
| 6 | css/scan.css, css/slider.css, js/api.js, js/slider.js, js/scan.js | Add SCAN button, slider, and API call |
| 7 | css/results.css, js/results.js | Add scan result summary cards |
| 8 | css/history.css, js/history.js | Add Results tab backed by the database |
| 9 | (docs/testing) README tweaks, end-to-end test with the real model, add preprocess.joblib snippet below | Test with real model, document live-traffic plan |

Notes
- Test the backend alone after day 4: `python ui/backend/app.py`, then
  `curl -X POST localhost:5000/api/scan -H "Content-Type: application/json" -d '{"records":500}'`
- For live traffic later, the imputer and scaler must be saved. Add this after Step 6 in cecs451proj.py:
  `joblib.dump({'imputer': imp, 'scaler': std, 'columns': list(X_train.columns)}, os.path.join(HERE, 'preprocess.joblib'))`
- splits.joblib, best_model.joblib and pcap.parquet are large; keep them out of git (add to the root .gitignore).
