// Results tab: previous scans, loaded from the backend database.
const dash = (v) => (v === null || v === undefined ? "–" : v.toLocaleString());

async function renderHistory() {
  const el = $("hist");
  let list;
  try {
    list = await fetchHistory();
  } catch (e) {
    el.innerHTML = '<p class="empty">Could not load history. Is the backend running?</p>';
    return;
  }
  if (!list.length) {
    el.innerHTML = '<p class="empty">No scans yet. Run one from the Scan tab.</p>';
    return;
  }
  const rows = list.map((r) => {
    const date = new Date(r.created_at.replace(" ", "T") + "Z").toLocaleString(); // stored in UTC
    return `<tr><td>${date}</td><td>${dash(r.records)}</td><td>${r.seconds.toFixed(2)}s</td><td>${dash(r.malicious)}</td><td>${dash(r.missed)}</td><td>${dash(r.false_alarms)}</td><td>${r.status}</td></tr>`;
  }).join("");
  el.innerHTML =
    '<div class="scroll"><table><tr><th>DATE</th><th>WINDOWS</th><th>DURATION</th><th>FLAGGED</th><th>MISSED</th><th>FALSE ALARMS</th><th>STATUS</th></tr>' +
    rows + '</table></div><p><button class="sm" onclick="clearHistory()">Clear history</button></p>';
}

async function clearHistory() {
  await deleteHistory();
  renderHistory();
}
