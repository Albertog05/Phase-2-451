// SCAN button + progress ring.
const STEPS = ["Reading traffic windows...", "Checking packet sizes...", "Checking TCP flags...", "Checking packet rates...", "Scoring with the model..."];
const RING = 628; // circle circumference
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function setProgress(p) {
  $("bar").style.strokeDashoffset = RING - (RING * p) / 100;
}

// The model answers in well under a second, so the ring animates for a few
// seconds (longer for bigger scans) purely for the speed-test feel.
function animationMs(n) {
  return 2000 + (3000 * (n - CONFIG.MIN_RECORDS)) / (CONFIG.MAX_RECORDS - CONFIG.MIN_RECORDS);
}

function initScan() {
  const go = $("go");
  let running = false;
  go.onclick = async () => {
    if (running) return;
    running = true;
    const n = typeof getRecordCount === "function" ? getRecordCount() : CONFIG.DEFAULT_RECORDS;
    go.disabled = true;
    $("rng").disabled = true;
    $("stats").hidden = true;
    $("err").hidden = true;
    const total = animationMs(n);
    const t0 = Date.now();
    const iv = setInterval(() => {
      const p = Math.min(100, ((Date.now() - t0) / total) * 100);
      setProgress(p);
      $("step").textContent = STEPS[Math.min(STEPS.length - 1, Math.floor((p / 100) * STEPS.length))];
      go.textContent = Math.round((n * p) / 100).toLocaleString();
    }, 50);
    const request = runScan(n).then((r) => ({ r }), (e) => ({ e }));
    const [outcome] = await Promise.all([request, sleep(total)]);
    clearInterval(iv);
    if (outcome.e) {
      $("err").textContent = "Scan failed: " + outcome.e.message + ". Is the backend running?";
      $("err").hidden = false;
    } else if (typeof showResults === "function") {
      showResults(outcome.r);
    }
    setProgress(0);
    go.textContent = "SCAN";
    $("step").textContent = "";
    go.disabled = false;
    $("rng").disabled = false;
    running = false;
  };
}
