package server

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
)

// rolesScript is the one inline script of the Apps pages. It fits each row's
// tokens to its width, turning those that do not fit into "+N more" (without
// it the row clips them), counts the unsaved changes on an app's page, and
// closes a picker on Escape. The page's Content-Security-Policy allows it by
// its hash and allows no other script.
const rolesScript template.JS = `(function () {
  function fit() {
    document.querySelectorAll("[data-fit]").forEach(function (w) {
      var more = w.querySelector(".tok.more");
      if (!more) return;
      var toks = Array.prototype.slice.call(w.querySelectorAll(".tok:not(.more):not(.add)"));
      toks.forEach(function (t) { t.hidden = false; });
      more.hidden = true;
      var n = 0;
      while (w.scrollWidth > w.clientWidth + 1 && n < toks.length) {
        n++;
        toks[toks.length - n].hidden = true;
        more.hidden = false;
        more.textContent = "+" + n + " more";
      }
      more.title = toks.slice(toks.length - n).map(function (t) {
        var l = t.querySelector(".l");
        return l ? l.textContent : "";
      }).join(", ");
    });
  }
  var words = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"];
  function count() {
    var f = document.getElementById("roles-form");
    if (!f) return;
    var n = 0;
    f.querySelectorAll("input.tick").forEach(function (i) {
      if (i.checked !== (i.getAttribute("data-held") === "1")) n++;
    });
    var bar = f.querySelector(".changes");
    bar.querySelector("[data-none]").hidden = n > 0;
    var some = bar.querySelector("[data-some]");
    some.hidden = n === 0;
    some.textContent = (words[n] || String(n)) + (n === 1 ? " change has" : " changes have") + " not been saved.";
    bar.querySelector("[data-discard]").hidden = n === 0;
    bar.className = "changes " + (n ? "some" : "none");
  }
  addEventListener("resize", fit);
  document.addEventListener("change", function (e) {
    if (e.target.classList && e.target.classList.contains("tick")) { count(); fit(); }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && location.hash.indexOf("#pick-") === 0) location.hash = "roles";
  });
  fit();
  count();
})();`

// scriptHash is the CSP source that allows exactly one inline script.
func scriptHash(script string) string {
	sum := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}
