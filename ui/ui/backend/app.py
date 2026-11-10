"""Flask API for the Network Malware Scanner UI.

Run from the repo root:  python ui/backend/app.py   then open http://localhost:5000
"""
from flask import Flask, jsonify, request, send_from_directory
import data_source
import db
import model_service

app = Flask(__name__, static_folder="../frontend", static_url_path="")

MIN_RECORDS, MAX_RECORDS = 100, 10000  # keep in sync with frontend/js/config.js

db.init_db()
data_source.load_test_set()
model_service.load_model()


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    try:
        count = int(data.get("records", 0))
    except (TypeError, ValueError):
        return jsonify(error="records must be a number"), 400
    if not MIN_RECORDS <= count <= MAX_RECORDS:
        return jsonify(error=f"records must be between {MIN_RECORDS} and {MAX_RECORDS}"), 400
    result = model_service.scan(count)
    result["id"] = db.save_scan(result)
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def history():
    return jsonify(db.list_scans())


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    db.clear_scans()
    return jsonify(ok=True)


if __name__ == "__main__":
    print("Model:", model_service.model_info())
    app.run(debug=False)
