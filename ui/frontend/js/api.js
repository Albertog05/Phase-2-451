// Calls to the Flask backend.
async function runScan(records) {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ records }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || "Scan failed (" + res.status + ")");
  }
  return res.json();
}

async function fetchHistory() {
  const res = await fetch("/api/history");
  if (!res.ok) throw new Error("History request failed");
  return res.json();
}

async function deleteHistory() {
  await fetch("/api/history", { method: "DELETE" });
}
