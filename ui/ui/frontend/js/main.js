// Entry point. Each module is optional so the page keeps working while
// features are committed one by one.
addEventListener("hashchange", route);
route();
if (typeof initSlider === "function") initSlider();
if (typeof initScan === "function") initScan();
