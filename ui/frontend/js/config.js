// Central settings. Keep MIN/MAX in sync with MIN_RECORDS/MAX_RECORDS in backend/app.py.
// Each record is one window of network traffic (one row of the dataset).
const CONFIG = {
  MIN_RECORDS: 100,
  MAX_RECORDS: 2000,
  STEP_RECORDS: 100,
  DEFAULT_RECORDS: 1000,
  UNIT: "traffic windows",
};
// Final held-out test results, shown in the performance panel.
const FINAL_TEST = { recall: 0.9897, precision: 0.9891, f1: 0.9894, auc: 0.9982, missed: 350, falseAlarms: 372 };

const $ = (id) => document.getElementById(id);
