
'''pip install pyarrow
The first portion of our project is to get a dataset that will be used to train and develop our ai model
We will be using CIC-YNU-IoTMal Dataset 2026 by Canadian Institue for Cybyersecurity
we installed pcap.parquet whihc ontains processed network traffic captured during malware execetion as a parquet file
'''
#------------------------IMPORTS-------------------------------------------------------------------
import pandas as pd 
import numpy as np



#--------------------------------------------------------------------------------------------
#Load the data frame
df = pd.read_parquet("pcap.parquet")
print(f"Total Amount of Rows loaded: {len(df)} from the pcap.parquet")
# Exploring the data!!!!! To gather crucial insights on what we are working wiht

#What columns and rows exist??(total of 455,641 rows with 42 colums)
print(df.head())
print(df.shape)
#missing values(missing 433 rows, )
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
print("---------STEP 3: Encoding--------")
print("\n--- STEP 3 ---")
print(f"Encoded X shape: {X.shape}")
print("Class balance (rows):")
print(y.value_counts())
#------------------------