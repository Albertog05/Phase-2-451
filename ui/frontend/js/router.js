// Hash routing between the Scan and Results views.
function route() {
  const view = location.hash === "#history" ? "history" : "scan";
  $("v-scan").classList.toggle("on", view === "scan");
  $("v-history").classList.toggle("on", view === "history");
  $("n-scan").classList.toggle("on", view === "scan");
  $("n-history").classList.toggle("on", view === "history");
  if (view === "history" && typeof renderHistory === "function") renderHistory();
}
