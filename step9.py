#step9.py

#CECS 451 Phase 2: Step 9, score the winning model on the TEST set ONE time. Do not rerun to tweak anything.

import os
import joblib
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))

THRESHOLD = 0.2   #chosen on the VALIDATION threshold sweep in tunning.py, not on test

d = joblib.load(os.path.join(HERE, 'splits.joblib'))
X_test, y_test = d['X_test'], d['y_test']

b = joblib.load(os.path.join(HERE, 'best_model.joblib'))
model = b['model']
print("Model:", b['name'], "| threshold:", THRESHOLD)

proba = model.predict_proba(X_test)[:, 1]
pred  = (proba >= THRESHOLD).astype(int)
cm    = confusion_matrix(y_test, pred)

print("\n--- STEP 9: FINAL TEST RESULTS ---")
print(f"   Recall:    {recall_score(y_test, pred):.4f}")
print(f"   Precision: {precision_score(y_test, pred):.4f}")
print(f"   F1:        {f1_score(y_test, pred):.4f}")
print(f"   ROC AUC:   {roc_auc_score(y_test, proba):.4f}")
print(f"   Confusion matrix [[TN FP] [FN TP]]:\n{cm}")
print(f"   Missed malware: {cm[1, 0]} | False alarms: {cm[0, 1]}")

#saves the threshold with the model so app.py uses the same one
b['threshold'] = THRESHOLD
joblib.dump(b, os.path.join(HERE, 'best_model.joblib'))
print("\nSaved threshold into best_model.joblib") 
