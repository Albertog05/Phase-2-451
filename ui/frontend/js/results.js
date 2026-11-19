// Summary cards under the slider after a scan.
function showResults(r) {
  const cards = [
    ["Records scanned", r.records.toLocaleString()],
    ["Duration", r.seconds.toFixed(2) + " s"],
    ["Malicious found", r.malicious.toLocaleString()],
    ["Status", r.status],
  ];
  // only present when the records have true labels (test data, not live traffic)
  if (r.accuracy !== null) {
    cards.push(["Accuracy", (r.accuracy * 100).toFixed(1) + "%"],
               ["Missed malware", r.missed.toLocaleString()],
               ["False alarms", r.false_alarms.toLocaleString()]);
  }
  $("stats").innerHTML = cards
    .map(([label, value]) => `<div class="stat"><small>${label}</small><span>${value}</span></div>`)
    .join("");
  $("stats").hidden = false;
}
