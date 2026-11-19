
'''pip install pyarrow
The first portion of our project is to get a dataset that will be used to train and develop our ai model
We will be using CIC-YNU-IoTMal Dataset 2026 by Canadian Institue for Cybyersecurity
we installed pcap.parquet whihc ontains processed network traffic captured during malware execetion as a parquet file
'''
#------------------------IMPORTS-------------------------------------------------------------------
import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score

#folder of this script, so every file is read and saved next to it no matter where the script is run from
HERE = os.path.dirname(os.path.abspath(__file__))

#=======================BASELINE MODELS (PHASE 1)=======================
#--------------------------------------------------------------------------------------------
#Load the data frame
df = pd.read_parquet(os.path.join(HERE, "pcap.parquet"))
print(f"Total Amount of Rows loaded: {len(df)} from the pcap.parquet")
# Exploring the data!!!!! To gather crucial insights on what we are working wiht

#What columns and rows exist??(total of 455,641 rows with 42 colums)
print(df.head())
print(df.shape)
#missing values(483 in Std and Variance)
print(df.isna().sum()[lambda s: s > 0])
print("Duplicate rows:", df.duplicated().sum())#total of 77 dups
print("\nLabels:")
print(df['MalwareFamily'].value_counts())
print("\nProtocol Type values:", df['Protocol Type'].value_counts().to_dict())#encoded values

#CREATE METADATA, to orgnaize the information
not_features = {
    'Hash':          ('group_id',     'sample ID, keeps a sample in one split'),
    'MalwareFamily': ('label_source', 'source of the target'),
    'Arch':          ('drop',         'constant (always x86)'),
    'SMTP':          ('drop',         'constant (always 0)'),
    'IRC':           ('drop',         'constant (always 0)'),
    'Tot size':      ('drop',         'exact copy of AVG'),
    'Variance':      ('drop',         'exactly Std squared'),
    'Tot sum':       ('drop',         'exactly AVG x Number'),
    'Number':        ('drop',         'window-size artifact'),
}
METADATA = {}
for col in df.columns:
    role, reason = not_features.get(col, ('feature', 'per-window traffic measurement'))
    METADATA[col] = {'role': role, 'reason': reason, 'dtype': str(df[col].dtype)}

print("\nMETADATA roles:")
print(pd.Series({c: i['role'] for c, i in METADATA.items()}).value_counts())
print("inf values:", int(np.isinf(df.select_dtypes(include='number')).sum().sum()))
print("Constant columns:", [c for c in df.columns if df[c].nunique() == 1])
#-----------------------Step 1-9 pipeline------------------------------__________

#Step 1: Extract ---------------------
#converted inf to NaN, removed unknown lables and dropped the dups total 424,033 rows
baseline_df = df.replace([np.inf, -np.inf], np.nan)          # inf -> NaN (Step 5 fills it)
baseline_df = baseline_df[baseline_df['MalwareFamily'] != 'Unknown']   # no ground truth
baseline_df = baseline_df.drop_duplicates().reset_index(drop=True)
print("\n--- STEP 1 ---")
print("Baseline rows:", len(baseline_df))
#-----------------------Step 2 Feature Selection-------------------------------
#features we are using: header length, ttl, rate, tcp flag fields and couints, http, dns, tcp, udp, min,max,avg,std,iat,protocal type
#features dropped: smtp, irc and atch, tot size, variance, tot sum, number
#target y = malware familily
#here we select our x and y using the metadata
selected_features=[c for c, i in METADATA.items() if i['role'] == 'feature']
X      = baseline_df[selected_features]
y      = baseline_df['MalwareFamily']
groups = baseline_df['Hash']
print("\n--- STEP 2 Feature selection---")
print(f"Baseline X shape: {X.shape}")
print(f"Baseline y shape: {y.shape}")
#-----------------------Step 3:Encoding Categorical Data--------------
#Our data is either orginal encoding or one hot encoding. However, since it is categorical we will use one hot encoding
#one hot encoding is either 0s or 1s, hot or cold etc, its nominal meaning theres no natural ordering.
#use pd.get_dummies()
#malwarefamily is binary
y = (y != 'Benign').astype(int) #1 = mal, 0 =benign

X = X.copy()
X['Protocol Type'] = X['Protocol Type'].astype(str)  # code, not a quantity
X = pd.get_dummies(X, columns=['Protocol Type'], dtype=int)
print("\n--- STEP 3 ---")
print(f"Encoded X shape: {X.shape}")
print("Class balance (rows):")
print(y.value_counts())
#------------------------
#Step 4 TRAIN TEST SPLIT
#We will use stratified group k fold to split the data into train and test sets.
sgkf = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=42)
folds = [test_idx for _, test_idx in sgkf.split(X, y, groups)]

test_idx  = folds[0]                    # 1 fold  -> test
val_idx   = folds[1]                    # 1 fold  -> validation
train_idx = np.concatenate(folds[2:])   # 8 folds -> train

X_train, y_train, g_train = X.iloc[train_idx], y.iloc[train_idx], groups.iloc[train_idx]
X_val,   y_val            = X.iloc[val_idx],   y.iloc[val_idx]
X_test,  y_test           = X.iloc[test_idx],  y.iloc[test_idx]

print("\n--- STEP 4 ---")
print(f"Training set size:   {X_train.shape[0]} samples")
print(f"Validation set size: {X_val.shape[0]} samples")
print(f"Test set size:       {X_test.shape[0]} samples")

print("\nMalicious share (should be similar in each):")
print(f"Train: {y_train.mean():.3f} | Val: {y_val.mean():.3f} | Test: {y_test.mean():.3f}")

g_val, g_test = set(groups.iloc[val_idx]), set(groups.iloc[test_idx])
g_tr = set(g_train)
print("\nSamples (Hash) shared between sets (all must be 0):")
print("Train & Val:", len(g_tr & g_val), "| Train & Test:", len(g_tr & g_test), "| Val & Test:", len(g_val & g_test))
#-----------------------Step 5: Fill Missing Values-------------------------------
#only the training sets that have missing values are rate and std.
print("\n--- STEP 5 ---")
print("Missing values in training set:")
print(X_train.isnull().sum()[lambda s: s > 0])
print("\nMissing values in validation set:")
print(X_val.isnull().sum()[lambda s: s > 0])
print("\nMissing values in test set:")
print(X_test.isnull().sum()[lambda s: s > 0])

#fit on TRAIN only, then apply the same medians to validation and test (no leakage)
imp     = SimpleImputer(strategy='median')
X_train = pd.DataFrame(imp.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
X_val   = pd.DataFrame(imp.transform(X_val),       columns=X_val.columns,   index=X_val.index)
X_test  = pd.DataFrame(imp.transform(X_test),      columns=X_test.columns,  index=X_test.index)

print("\nMissing values after imputing (train / val / test):")
print(X_train.isna().sum().sum(), X_val.isna().sum().sum(), X_test.isna().sum().sum())
#-----------------------Step 6: Feature Scaling-------------------------------
std     = StandardScaler()
X_train = pd.DataFrame(std.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
X_val   = pd.DataFrame(std.transform(X_val),       columns=X_val.columns,   index=X_val.index)
X_test  = pd.DataFrame(std.transform(X_test),      columns=X_test.columns,  index=X_test.index)

print("\n--- STEP 6 ---")
print("Training set after standardizing (mean should be ~0, std ~1):")
print(round(X_train.describe().loc[['mean', 'std']], 2))

#save the processed splits so tunning.py can load them
joblib.dump({'X_train': X_train, 'y_train': y_train, 'g_train': g_train,
             'X_val': X_val, 'y_val': y_val, 'X_test': X_test, 'y_test': y_test},
            os.path.join(HERE, 'splits.joblib'))
print("Saved splits.joblib")
joblib.dump({'imputer': imp, 'scaler': std, 'columns': list(X_train.columns)}, os.path.join(HERE, 'preprocess.joblib'))
print("Saved preprocess.joblib")
#-----------------------Step 7: Fit the baseline models-------------------------------
def evaluate(model, X_data, y_data):
    pred  = model.predict(X_data)
    proba = model.predict_proba(X_data)[:, 1]      # probability of malicious, needed for ROC AUC
    return {'recall': recall_score(y_data, pred), 'precision': precision_score(y_data, pred),
            'f1': f1_score(y_data, pred), 'auc': roc_auc_score(y_data, proba),
            'cm': confusion_matrix(y_data, pred)}

def show(res):
    print(f"   Recall:    {res['recall']:.4f}")
    print(f"   Precision: {res['precision']:.4f}")
    print(f"   F1:        {res['f1']:.4f}")
    print(f"   ROC AUC:   {res['auc']:.4f}")
    print(f"   Confusion matrix [[TN FP] [FN TP]]:\n{res['cm']}")

#MODEL 1: Logistic Regression (baseline)
print("\nMODEL 1: LOGISTIC REGRESSION")
lr_base = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
lr_base.fit(X_train, y_train)
lr_train = evaluate(lr_base, X_train, y_train)
lr_val   = evaluate(lr_base, X_val, y_val)
print("\nTraining Results:")
show(lr_train)
print("\nValidation Results:")
show(lr_val)

#MODEL 2: Decision Tree (default depth, so expect it to overfit)
print("\nMODEL 2: DECISION TREE")
tree_base = DecisionTreeClassifier(class_weight='balanced', random_state=42)
tree_base.fit(X_train, y_train)
tree_train = evaluate(tree_base, X_train, y_train)
tree_val   = evaluate(tree_base, X_val, y_val)
print("\nTraining Results:")
show(tree_train)
print("\nValidation Results:")
show(tree_val)
feat_df = pd.DataFrame({'Feature': X_train.columns, 'Importance': tree_base.feature_importances_}).sort_values('Importance', ascending=False)
print("\nFeature Importance (top 10):")
print(feat_df.head(10).round(4))

#MODEL 3: Random Forest (default 100 trees)
print("\nMODEL 3: RANDOM FOREST")
rf_base = RandomForestClassifier(class_weight='balanced', random_state=42, n_jobs=-1)
rf_base.fit(X_train, y_train)
rf_train = evaluate(rf_base, X_train, y_train)
rf_val   = evaluate(rf_base, X_val, y_val)
print("\nTraining Results:")
show(rf_train)
print("\nValidation Results:")
show(rf_val)

#STEP 8: compare the three on VALIDATION, pick by recall then F1
results = pd.DataFrame({
    'Logistic Regression': {k: lr_val[k]   for k in ['recall', 'precision', 'f1', 'auc']},
    'Decision Tree':       {k: tree_val[k] for k in ['recall', 'precision', 'f1', 'auc']},
    'Random Forest':       {k: rf_val[k]   for k in ['recall', 'precision', 'f1', 'auc']},
}).T.sort_values(['recall', 'f1'], ascending=False)
print("\n--- STEP 8: BASELINE COMPARISON (validation) ---")
print(results.round(4))
print("Best baseline:", results.index[0])

#results were very high, however the issue might be that the benign data is
#like IoT traffc(UDP, DHCP, ARP and ICMP), while malware is mostly TCP scanning, so the model
#might be learning the protocol type rather than the actual malware behavior.
#we will retrain it again this time wihtout protocol columns to see if the model can still learn the malware behavior without the protocol type being a feature.

#=======================PHASE 2: BEHAVIOR, FIXES AND TESTING=======================
#Testing theories about WHY the baseline scores are so high. Validation set only, the test set stays untouched.

#-----Theory 1: the models mostly learn "mostly TCP = malicious"-----
#Evidence: the decision tree's top feature is TCP at 0.894 importance, everything else is under 0.04.
#Concern: the benign data looks like IoT background traffic (UDP, DHCP, ARP, ICMP) and the malware is mostly TCP scanning,
#so on a real network where normal browsing is also TCP the scores could drop.
#Test: retrain Random Forest without the protocol columns and see how far the scores drop.
protocol_cols = ['HTTP', 'HTTPS', 'DNS', 'Telnet', 'SSH', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC'] \
                + [c for c in X_train.columns if c.startswith('Protocol Type_')]
tests = {'drop TCP only': ['TCP'],
         'drop all protocol columns': protocol_cols}

#the first row is the baseline Random Forest from Step 7 (no refit needed)
rows = {'all features (baseline)': {'features': X_train.shape[1], 'recall': rf_val['recall'], 'precision': rf_val['precision'],
                                    'f1': rf_val['f1'], 'auc': rf_val['auc'],
                                    'missed': rf_val['cm'][1, 0], 'false alarms': rf_val['cm'][0, 1]}}
print("\n--- PHASE 2, THEORY 1: PROTOCOL COLUMNS ---")
for name, drop in tests.items():
    cols = [c for c in X_train.columns if c not in drop]
    rf_t = RandomForestClassifier(class_weight='balanced', random_state=42, n_jobs=-1)
    rf_t.fit(X_train[cols], y_train)
    res = evaluate(rf_t, X_val[cols], y_val)
    rows[name] = {'features': len(cols), 'recall': res['recall'], 'precision': res['precision'],
                  'f1': res['f1'], 'auc': res['auc'], 'missed': res['cm'][1, 0], 'false alarms': res['cm'][0, 1]}
    feat_imp = pd.Series(rf_t.feature_importances_, index=cols).sort_values(ascending=False)
    print(f"\n{name}: top 5 features")
    print(feat_imp.head(5).round(4))
print("\nValidation results:")
print(pd.DataFrame(rows).T.round(4))

#-----Theory 2: the model catches Mirai but misses the smaller families-----
#Mirai is about 70% of the malicious rows, so a high overall recall could hide weak spots.
#For the malware families the number below is the recall. For Benign it is the false alarm rate.
print("\n--- PHASE 2, THEORY 2: RESULTS BY FAMILY (baseline Random Forest, validation) ---")
fam     = baseline_df.loc[X_val.index, 'MalwareFamily']
flagged = pd.Series(rf_base.predict(X_val), index=X_val.index)
print(pd.DataFrame({'family': fam, 'flagged': flagged}).groupby('family')['flagged'].agg(['mean', 'count']).round(4))

#THEORY 1 RESULT: dropping TCP changed nothing (F1 0.9897). Dropping all 17 protocol columns cost only 0.0009 F1
#(486 missed vs 449). The tree's 0.894 TCP importance came from correlated features (syn_count, syn_flag_number, Header_Length)
#sharing one signal, not from a protocol shortcut. Keep all 36 features. SYN flags and header length still reveal TCP,
#so this does not prove the model ignores protocol.
#THEORY 2 RESULT: recall by family is 98.6% to 100% for every family, so no family is missed. Benign false alarm rate is 3.05%.
#Remaining risk: lab data vs real traffic (LLM-generated benign, IoT malware). Expect lower live scan scores.