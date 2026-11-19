#Here we tune the model using different hyperparameter settings. The best one is refit on the full training set and saved for later use.

#Idea: try different settings for each model, compare against the baseline, keep the best one

#1 Logistic Regression
#C = regularization strength, small C = simpler model, large C = more complex model
#penalty: l2 shrinks all weights toward zero, l1 can set weak weights to exactly zero (sparse model)

#2 Decision Tree
#max_depth = how many questions deep the tree goes
#min_samples_leaf = rows needed in a leaf, 1 = very complex tree, bigger = simpler tree
#criterion = how a split is scored (gini or entropy), usually gives nearly the same result

#3 Random Forest
#n_estimators = number of trees, more trees = more stable (costs time, does not overfit more)
#max_depth = how deep each tree goes, more depth = more complex
#min_samples_leaf = rows needed in a leaf, more rows = simpler
#max_features = features each split may look at, more features = more complex
#class_weight = how much each class's errors count (balanced gives the rarer class more weight)
import os, warnings
os.environ["PYTHONWARNINGS"] = "ignore"   # also reaches the parallel workers
warnings.filterwarnings("ignore")
#----------------IMPORTS---------------------------------
import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.model_selection import StratifiedGroupKFold, cross_val_score, GridSearchCV, RandomizedSearchCV
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score

#folder of this script, so files are found no matter where the script is run from
HERE = os.path.dirname(os.path.abspath(__file__))

#------------------------SETTINGS-------------------------------------------------------------------
CHOOSE_K_ONLY = False  #True = only print the K table and stop. After choosing K, set this to False and run again
K= 5    #set this after reading the K table

#-----SECTION 0: LOAD DATA AND CHOOSE THE NUMBER OF FOLDS-----------------------
d = joblib.load(os.path.join(HERE, 'splits.joblib'))
X_train, y_train, g_train = d['X_train'], d['y_train'], d['g_train']
X_val,   y_val            = d['X_val'],   d['y_val']
#the test set is NOT loaded here, it is only used once at the very end (Step 9)

#100,000 rows is enough to compare settings and keeps the searches fast. The winners are refit on the full training set
sub = X_train.sample(n=100000, random_state=42).index
X_sub, y_sub, g_sub = X_train.loc[sub], y_train.loc[sub], g_train.loc[sub]

if CHOOSE_K_ONLY:
    #compare k with logistic regression (fast). groups keeps every Hash (malware sample) inside ONE fold
    print("\n--- CHOOSING K (F1, Logistic Regression, grouped folds) ---")
    lr_k = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
    for k in [3, 5, 7, 10]:
        cv_k   = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=42)
        start  = time.time()
        scores = cross_val_score(lr_k, X_sub, y_sub, groups=g_sub, cv=cv_k, scoring='f1')
        print(f"k={k:>2}  mean={scores.mean():.4f}  std={scores.std():.4f}  min={scores.min():.4f}  time={time.time()-start:.0f}s")
    print("\nSet K at the top, set CHOOSE_K_ONLY = False and run again.")
    raise SystemExit

cv = StratifiedGroupKFold(n_splits=K, shuffle=True, random_state=42)   #same folds for every model

#baseline validation scores from Step 8 of pipeline_model.py (default settings, random_state=42)
baseline = {'Logistic Regression': {'recall': 0.9628, 'precision': 0.9986, 'f1': 0.9804, 'auc': 0.9962, 'missed': 1269, 'false alarms': 45},
            'Decision Tree':       {'recall': 0.9865, 'precision': 0.9883, 'f1': 0.9874, 'auc': 0.9692, 'missed': 460,  'false alarms': 398},
            'Random Forest':       {'recall': 0.9868, 'precision': 0.9926, 'f1': 0.9897, 'auc': 0.9969, 'missed': 449,  'false alarms': 252}}

#--Helpers for easy result(same metrics as Step 7 and 8)------------------------------------
def evaluate(model, X_data, y_data):
    pred  = model.predict(X_data)
    proba = model.predict_proba(X_data)[:, 1]
    return {'recall': recall_score(y_data, pred), 'precision': precision_score(y_data, pred),
            'f1': f1_score(y_data, pred), 'auc': roc_auc_score(y_data, proba),
            'cm': confusion_matrix(y_data, pred)}

def show(res):
    print(f"   Recall:    {res['recall']:.4f}")
    print(f"   Precision: {res['precision']:.4f}")
    print(f"   F1:        {res['f1']:.4f}")
    print(f"   ROC AUC:   {res['auc']:.4f}")
    print(f"   Confusion matrix [[TN FP] [FN TP]]:\n{res['cm']}")

def run_search(name, search):
    #First search on the subsample with grouped folds, 2. refit the best settings on the FULL training set, 3. score on validation
    print(f"\n--- {name}: SEARCH ({K} folds) ---")
    start = time.time()
    search.fit(X_sub, y_sub, groups=g_sub)
    print(f"Search time: {time.time()-start:.0f}s")
    print("Best settings:", search.best_params_)
    print(f"Best cross validation F1: {search.best_score_:.4f}")
    r = pd.DataFrame(search.cv_results_).sort_values('rank_test_score')
    print("\nTop 5 combinations:")
    print(r[['params', 'mean_test_score', 'std_test_score']].head(5).to_string(index=False))
    final = clone(search.best_estimator_)
    final.fit(X_train, y_train)
    res = evaluate(final, X_val, y_val)
    print(f"\n{name} (tuned, refit on the full training set), validation results:")
    show(res)
    return final, res
models  = {}
results = {}

#------------------------SECTION 1: LOGISTIC REGRESSION-------------------------------------------
#liblinear is the solver that supports both penalties. 4 x 2 =8 combinations
lr_search = GridSearchCV(LogisticRegression(solver='liblinear', class_weight='balanced', max_iter=200, tol=1e-3, random_state=42),
                         param_grid={'C': [0.01, 0.1, 1, 10], 'penalty': ['l1', 'l2']},
                         cv=cv, scoring='f1', n_jobs=1, verbose=3)
models['Logistic Regression'], results['Logistic Regression'] = run_search('LOGISTIC REGRESSION', lr_search)

#-------------------SECTION 2: DECISION TREE-------------------------------------------------
#the baseline tree memorized the training set (train 1.0000, validation AUC 0.9692), so these settings limit how much it can memorize
#5 x 4 x 2 = 40 combinations, all tried
tree_search = GridSearchCV(DecisionTreeClassifier(class_weight='balanced', random_state=42),
                           param_grid={'max_depth': [5, 10, 15, 20, None],
                                       'min_samples_leaf': [1, 5, 20, 50],
                                       'criterion': ['gini', 'entropy']},
                           cv=cv, scoring='f1', n_jobs=-1)
models['Decision Tree'], results['Decision Tree'] = run_search('DECISION TREE', tree_search)

#--------SECTION 3: RANDOM FOREST---------------------------------
#288 possible combinations is too many for a forest, so RandomizedSearchCV tries 15 random ones
#if this takes too long, lower n_iter to 8
rf_search = RandomizedSearchCV(RandomForestClassifier(random_state=42, n_jobs=-1),
                               param_distributions={'n_estimators': [100, 200, 300],
                                                    'max_depth': [10, 20, 30, None],
                                                    'min_samples_leaf': [1, 2, 5, 10],
                                                    'max_features': ['sqrt', 'log2', 0.5],
                                                    'class_weight': ['balanced', 'balanced_subsample']},
                               n_iter=15, cv=cv, scoring='f1', random_state=42, n_jobs=1)
models['Random Forest'], results['Random Forest'] = run_search('RANDOM FOREST', rf_search)

#------------------------SECTION 4: COMPARE BASELINE VS TUNED (validation)------------------------
rows = {}
for name in results:
    rows[f'{name} (baseline)'] = baseline[name]
    rows[f'{name} (tuned)']    = {k: results[name][k] for k in ['recall', 'precision', 'f1', 'auc']}
    rows[f'{name} (tuned)']['missed']       = results[name]['cm'][1, 0]
    rows[f'{name} (tuned)']['false alarms'] = results[name]['cm'][0, 1]
compare = pd.DataFrame(rows).T
print("\n--- BASELINE VS TUNED (validation) ---")
print(compare.round(4))

#winner = best tuned model, ranked by recall then F1
tuned     = compare.loc[[n for n in compare.index if 'tuned' in n]].sort_values(['recall', 'f1'], ascending=False)
best_name = tuned.index[0].replace(' (tuned)', '')
winner    = models[best_name]
print("\nBest tuned model:", best_name)

#------------------------SECTION 5: DECISION THRESHOLD FOR THE WINNER (validation)----------------
#by default a flow is called malicious above 0.5. A lower threshold catches more malware but raises false alarms
proba = winner.predict_proba(X_val)[:, 1]
print(f"\n--- THRESHOLD SWEEP ({best_name}, validation) ---")
print("threshold  recall  precision  f1      missed  false alarms")
for t in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
    pred = (proba >= t).astype(int)
    cm   = confusion_matrix(y_val, pred)
    print(f"{t:<10} {recall_score(y_val, pred):.4f}  {precision_score(y_val, pred):.4f}     {f1_score(y_val, pred):.4f}  {cm[1, 0]:<7} {cm[0, 1]}")

#-------------SAVE----------------
compare.to_csv(os.path.join(HERE, 'tuning_results.csv'))
joblib.dump({'model': winner, 'name': best_name, 'columns': list(X_train.columns)}, os.path.join(HERE, 'best_model.joblib'))
print("\nSaved tuning_results.csv and best_model.joblib")