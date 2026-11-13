package server

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
)

// rolesScript is the one inline script of the Apps pages. It fits each row's
// tokens to its width, turning those that do not fit into "+N more", which
// lists them when pressed (without the script the overview shows the first
// tokens and "+N more" from the server). Tokens are hidden least important
// first: other holders from the end, then the holder that sets the widest
// access, then the card token, and last the tokens a check matched; the
// last token left shrinks rather than being hidden. It also counts the unsaved changes on an app's page, moves focus
// into a picker when it opens and back to its Add token when it closes, and
// closes a picker on Escape. The page's Content-Security-Policy allows it by
// its hash and allows no other script.
const rolesScript template.JS = `(function () {
  var pop = null;
  function closeMore(focus) {
    if (!pop) return;
    var m = pop.owner;
    pop.remove();
    pop = null;
    m.setAttribute("aria-expanded", "false");
    if (focus) m.focus();
  }
  function rank(t) { return t.classList.contains("on") ? 4 : t.classList.contains("card") ? 3 : t.classList.contains("widest") ? 2 : 1; }
  function fit() {
    closeMore(false);
    document.querySelectorAll("[data-fit]").forEach(function (w) {
      var more = w.querySelector(".tok.more");
      if (!more) return;
      var toks = Array.prototype.slice.call(w.querySelectorAll(".tok:not(.more):not(.add)"));
      toks.forEach(function (t) { t.hidden = false; t.classList.remove("shrink", "capped"); });
      more.hidden = true;
      var order = toks.map(function (t, i) { return i; }).sort(function (a, b) {
        var d = rank(toks[a]) - rank(toks[b]);
        return d !== 0 ? d : b - a;
      });
      var n = 0;
      while (w.scrollWidth > w.clientWidth + 1 && n < toks.length - 1) {
        toks[order[n]].hidden = true;
        n++;
        more.hidden = false;
        more.textContent = "+" + n + " more";
      }
      if (w.scrollWidth > w.clientWidth + 1) {
        toks.forEach(function (t) { if (!t.hidden) t.classList.add("shrink"); });
      }
      more.title = toks.filter(function (t) { return t.hidden; }).map(function (t) {
        var l = t.querySelector(".l");
        return l ? l.textContent : "";
      }).join(", ");
    });
  }
  function openMore(m) {
    closeMore(false);
    var w = m.closest("[data-fit]");
    pop = document.createElement("div");
    pop.className = "morepop";
    pop.owner = m;
    w.querySelectorAll(".tok:not(.more):not(.add)").forEach(function (t) {
      if (!t.hidden) return;
      var c = t.cloneNode(true);
      c.hidden = false;
      c.classList.remove("shrink", "capped");
      var tick = t.querySelector("input.tick");
      if (tick) {
        c.querySelectorAll("input").forEach(function (i) { i.remove(); });
        c.setAttribute("tabindex", "0");
        c.setAttribute("role", "checkbox");
        c.setAttribute("aria-checked", tick.checked ? "true" : "false");
        c.addEventListener("click", function (e) { e.preventDefault(); tick.click(); });
        c.addEventListener("keydown", function (e) { if (e.key === " " || e.key === "Enter") { e.preventDefault(); tick.click(); } });
      }
      pop.appendChild(c);
    });
    document.body.appendChild(pop);
    var r = m.getBoundingClientRect();
    pop.style.top = Math.min(r.bottom + 4, innerHeight - pop.offsetHeight - 8) + "px";
    pop.style.left = Math.max(8, Math.min(r.left, innerWidth - pop.offsetWidth - 8)) + "px";
    m.setAttribute("aria-expanded", "true");
    var first = pop.querySelector("a, [tabindex]");
    if (first) first.focus();
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
  var opener = null;
  function picker() {
    var h = location.hash;
    var p = h.indexOf("#pick-") === 0 ? document.getElementById(h.slice(1)) : null;
    if (p) {
      opener = document.querySelector("a.tok.add[href='" + h + "']");
      var first = p.querySelector("input.tick, .jump a, a[data-close]");
      (first || p).focus();
    } else if (opener) {
      opener.focus();
      opener = null;
    }
  }
  addEventListener("resize", fit);
  addEventListener("hashchange", picker);
  document.addEventListener("change", function (e) {
    if (e.target.classList && e.target.classList.contains("tick")) { count(); fit(); }
  });
  document.addEventListener("click", function (e) {
    var m = e.target.closest && e.target.closest(".tok.more");
    if (m) {
      e.preventDefault();
      if (pop && pop.owner === m) closeMore(true); else openMore(m);
    } else if (pop && !pop.contains(e.target)) {
      closeMore(false);
    }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    if (pop) { closeMore(true); return; }
    if (location.hash.indexOf("#pick-") === 0) location.hash = "roles";
  });
  fit();
  count();
  picker();
})();`

// scriptHash is the CSP source that allows exactly one inline script.
func scriptHash(script string) string {
	sum := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}
