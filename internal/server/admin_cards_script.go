package server

import "html/template"

// The inline scripts of the new-card form and the design editor. Each one
// re-fetches the card's SVG preview for the values in the form as they
// change; the page's Content-Security-Policy allows it by its hash (see
// renderAdmin). Without a script, each form has a button that shows the
// preview for its values, and the presets and choices work as plain form
// controls.

const cardFormScript template.JS = `(function () {
  var f = document.getElementById("nc");
  if (!f) return;
  document.querySelectorAll("[data-nojs]").forEach(function (e) { e.hidden = true; });
  var timer;
  function val(name) { var e = f.querySelector("input[name='" + name + "']:checked"); return e || null; }
  function update() {
    var app = val("app"), design = val("design");
    var q = "label=" + encodeURIComponent(f.elements.label.value.trim());
    if (app) q += "&app=" + encodeURIComponent(app.getAttribute("data-label"));
    document.querySelectorAll("img[data-design]").forEach(function (i) {
      i.src = "/admin/break/preview.svg?design=" + i.getAttribute("data-design") + "&" + q;
    });
    if (design) {
      document.getElementById("ncprev").src = "/admin/break/preview.svg?design=" + design.value + "&" + q;
      document.getElementById("nccap").textContent = design.getAttribute("data-caption");
    }
  }
  f.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(update, 250); });
  f.addEventListener("change", update);
})();`

const designScript template.JS = `(function () {
  var f = document.getElementById("de");
  if (!f) return;
  document.querySelectorAll("[data-nojs]").forEach(function (e) { e.hidden = true; });
  function rgb(h) { return [1, 3, 5].map(function (i) { return parseInt(h.slice(i, i + 2), 16); }); }
  function lum(h) {
    var c = rgb(h).map(function (v) { v /= 255; return v <= .03928 ? v / 12.92 : Math.pow((v + .055) / 1.055, 2.4); });
    return .2126 * c[0] + .7152 * c[1] + .0722 * c[2];
  }
  function contrast(a, b) { var x = lum(a), y = lum(b); return (Math.max(x, y) + .05) / (Math.min(x, y) + .05); }
  function checked(name) { var e = f.querySelector("input[name='" + name + "']:checked"); return e ? e.value : ""; }
  function setColour(key, v) {
    f.querySelector("input[name='" + key + "']").value = v;
    f.querySelector("input[name='" + key + "_hex']").value = v;
  }
  var timer;
  function update() {
    var header = f.elements.header.value, accent = f.elements.accent.value;
    var q = new URLSearchParams();
    q.set("id", f.getAttribute("data-id")); q.set("draft", "1");
    ["name", "header", "accent", "bar1", "bar2", "bar3", "title", "steps"].forEach(function (k) { q.set(k, f.elements[k].value); });
    if (f.elements.stripe.checked) q.set("stripe", "1");
    q.set("logo_source", checked("logo_source")); q.set("logo_mode", checked("logo_mode")); q.set("size", checked("size"));
    q.set("label", f.getAttribute("data-sample")); q.set("app", f.getAttribute("data-app"));
    document.getElementById("dprev").src = "/admin/break/designs/preview.svg?" + q.toString();
    var size = f.querySelector("input[name='size']:checked");
    if (size) document.getElementById("dcap").textContent = size.getAttribute("data-caption");
    document.getElementById("accentWarn").textContent = contrast(accent, "#ffffff") < 3 ? f.getAttribute("data-accent-warn") : "";
    var src = checked("logo_source"), mode = checked("logo_mode");
    var ink = src === "own" ? f.getAttribute("data-ink-own") : f.getAttribute("data-ink-site");
    var has = src !== "none" && !!ink;
    var best = has && contrast("#ffffff", header) >= contrast(ink, header) ? "white" : "asis";
    if (has && f.getAttribute(src === "own" ? "data-solid-own" : "data-solid-site") === "1") best = "panel";
    f.querySelectorAll("[data-rec]").forEach(function (e) { e.hidden = !has || e.getAttribute("data-rec") !== best; });
    var ok = !has || mode === "panel" || contrast(mode === "white" ? "#ffffff" : ink, header) >= 3;
    document.getElementById("logoWarn").textContent = ok ? "" : f.getAttribute(best === "white" ? "data-logo-warn-white" : "data-logo-warn-asis");
  }
  f.addEventListener("input", function (e) {
    var t = e.target;
    if (t.hasAttribute("data-hex") && /^#[0-9a-fA-F]{6}$/.test(t.value)) f.querySelector("input[name='" + t.getAttribute("data-hex") + "']").value = t.value.toLowerCase();
    if (t.type === "color") f.querySelector("input[name='" + t.name + "_hex']").value = t.value;
    clearTimeout(timer); timer = setTimeout(update, 250);
  });
  f.addEventListener("change", update);
  f.querySelectorAll("button[name='preset']").forEach(function (b) {
    b.addEventListener("click", function (e) {
      e.preventDefault();
      setColour("header", b.getAttribute("data-header"));
      setColour("accent", b.getAttribute("data-accent"));
      f.elements.stripe.checked = b.getAttribute("data-stripe") === "1";
      update();
    });
  });
})();`
