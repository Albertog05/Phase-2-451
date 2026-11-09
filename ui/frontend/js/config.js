// Central settings. Keep MIN/MAX in sync with MIN_RECORDS/MAX_RECORDS in backend/app.py.
// Each record is one window of network traffic (one row of the dataset).
const CONFIG = {
  MIN_RECORDS: 100,
  MAX_RECORDS: 10000,
  STEP_RECORDS: 100,
  DEFAULT_RECORDS: 1000,
  UNIT: "traffic windows",
};
const $ = (id) => document.getElementById(id);
