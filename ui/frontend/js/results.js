// Results shown under the slider after a scan: summary cards, top windows,
// important features, model performance, and a CSV download.
let lastReport = null;

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const card = (label, value) => `<div class="stat"><small>${label}</small><span>${value}</span></div>`;

function showResults(r) {
  lastReport = r;
  const cards = [
    card("Windows scanned", r.records.toLocaleString()),
    card("Windows flagged", r.malicious.toLocaleString()),
    card("Status", esc(r.status)),
    card("Duration", r.seconds.toFixed(2) + " s"),
  ];
  // only present because the demo windows have true labels
  if (r.accuracy !== null) {
    cards.push(card("Accuracy (demo only)", (r.accuracy * 100).toFixed(1) + "%"),
               card("Missed malware (demo only)", r.missed.toLocaleString()),
               card("False alarms (demo only)", r.false_alarms.toLocaleString()));
  }

  const top = r.windows.slice(0, 10).map((w) =>
    `<tr><td>${esc(w.window_id)}</td><td>${w.score.toFixed(1)}</td><td>${w.flagged ? "MALWARE" : "Benign"}</td><td>${w.severity}</td><td>${esc(w.true_label ?? "–")}</td></tr>`).join("");

  const maxImp = Math.max(...r.top_features.map((f) => f.importance), 0.001);
  const feats = r.top_features.length
    ? `<h3>Most important features</h3><ul class="feats">` +
      r.top_features.map((f) => `<li><span>${esc(f.feature)}</span><i style="width:${((f.importance / maxImp) * 100).toFixed(0)}%"></i><b>${f.importance}</b></li>`).join("") + "</ul>"
    : "";

  const t = FINAL_TEST;
  const perf = [card("Recall", t.recall.toFixed(4)), card("Precision", t.precision.toFixed(4)),
                card("F1", t.f1.toFixed(4)), card("ROC AUC", t.auc.toFixed(4)),
                card("Missed malware", t.missed.toLocaleString()), card("False alarms", t.falseAlarms.toLocaleString())].join("");

  $("stats").innerHTML =
    `<div class="cards">${cards.join("")}</div>` +
    `<h3>Top 10 highest-scoring windows</h3><div class="scroll"><table><tr><th>WINDOW</th><th>SCORE</th><th>VERDICT</th><th>SEVERITY</th><th>TRUE LABEL (DEMO)</th></tr>${top}</table></div>` +
    `<p><button class="sm" onclick="downloadReport(lastReport)">Download CSV</button></p>` +
    feats +
    `<h3>Model performance (final test set)</h3><div class="cards">${perf}</div>`;
  $("stats").hidden = false;
}

function downloadReport(r) {
  const rows = ["window_id,score,verdict,severity,true_label"].concat(
    r.windows.map((w) => [w.window_id, w.score, w.flagged ? "MALWARE" : "Benign", w.severity, w.true_label].join(",")));
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([rows.join("\n")], { type: "text/csv" }));
  a.download = "scan_report.csv";
  a.click();
}