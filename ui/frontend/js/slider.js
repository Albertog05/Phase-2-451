// Slider with a fixed minimum and maximum (see config.js).
function getRecordCount() {
  const v = Number($("rng").value);
  return Math.min(CONFIG.MAX_RECORDS, Math.max(CONFIG.MIN_RECORDS, v));
}

function initSlider() {
  const rng = $("rng");
  rng.min = CONFIG.MIN_RECORDS;
  rng.max = CONFIG.MAX_RECORDS;
  rng.step = CONFIG.STEP_RECORDS;
  rng.value = CONFIG.DEFAULT_RECORDS;
  $("min-label").textContent = CONFIG.MIN_RECORDS.toLocaleString();
  $("max-label").textContent = CONFIG.MAX_RECORDS.toLocaleString();
  const update = () => ($("amt").textContent = getRecordCount().toLocaleString() + " " + CONFIG.UNIT);
  rng.oninput = update;
  update();
}
