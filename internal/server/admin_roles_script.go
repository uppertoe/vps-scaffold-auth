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
// access, then the card token, and last the tokens a check matched or a
// change is pending on; the last token left shrinks rather than being
// hidden.
//
// On an app's page it also shows each change where it is made, before the
// review: a holder ticked in a picker appears on the role's row at once as a
// pending addition, whose cross unticks it; a person added in the picker
// appears the same way, carrying the address and end date the server checks
// again in the review; and each row's widest access and the changes bar are
// redrawn. It moves focus into a picker when it opens and back to its Add
// token when it closes, closes a picker on Escape without moving the page,
// and asks before the page is left with changes that have not been saved.
// The page's Content-Security-Policy allows it by its hash and allows no
// other script.
const rolesScript template.JS = `(function () {
  var pop = null;
  var form = document.getElementById("roles-form");
  function closeMore(focus) {
    if (!pop) return;
    var m = pop.owner;
    pop.remove();
    pop = null;
    m.setAttribute("aria-expanded", "false");
    if (focus) m.focus();
  }
  function pendingTok(t) {
    if (t.classList.contains("padd") || t.classList.contains("pdel")) return true;
    var i = t.querySelector("input.tick");
    return !!(i && !i.checked);
  }
  function rank(t) { return t.classList.contains("on") || pendingTok(t) ? 4 : t.classList.contains("card") ? 3 : t.classList.contains("widest") ? 2 : 1; }
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
      } else if (t.classList.contains("proxy")) {
        c.addEventListener("click", function (e) { e.preventDefault(); t.click(); });
      }
      pop.appendChild(c);
    });
    document.body.appendChild(pop);
    var r = m.getBoundingClientRect();
    pop.style.top = Math.min(r.bottom + 4, innerHeight - pop.offsetHeight - 8) + "px";
    pop.style.left = Math.max(8, Math.min(r.left, innerWidth - pop.offsetWidth - 8)) + "px";
    m.setAttribute("aria-expanded", "true");
    var first = pop.querySelector("a, button, [tabindex]");
    if (first) first.focus();
  }

  function rowOf(role) { return form ? form.querySelector(".rrow[data-role='" + role + "']") : null; }
  function place(row, t) {
    var w = row.querySelector(".rwho");
    w.insertBefore(t, w.querySelector(".tok.more") || w.querySelector(".tok.add"));
  }
  function icon(id) {
    var ns = "http://www.w3.org/2000/svg", s = document.createElementNS(ns, "svg"), u = document.createElementNS(ns, "use");
    s.setAttribute("class", "ico");
    s.setAttribute("aria-hidden", "true");
    u.setAttribute("href", "#" + id);
    s.appendChild(u);
    return s;
  }
  function span(cls, text) {
    var e = document.createElement("span");
    e.className = cls;
    if (text) e.textContent = text;
    if (cls === "x") e.setAttribute("aria-hidden", "true");
    return e;
  }
  // A holder ticked in a picker is shown on its row as a pending addition,
  // a button whose cross unticks it again.
  function syncPicks() {
    if (!form) return;
    form.querySelectorAll(".pickwrap").forEach(function (pw) {
      var row = rowOf(pw.id.slice(5));
      if (!row) return;
      pw.querySelectorAll("label.opt input.tick").forEach(function (i) {
        var p = null;
        row.querySelectorAll(".tok.proxy").forEach(function (x) { if (x.getAttribute("data-for") === i.value) p = x; });
        if (i.checked && !p) {
          var t = i.closest(".opt").querySelector(".tok");
          p = document.createElement("button");
          p.type = "button";
          p.className = t.className.replace(/\bstatic\b/, "") + " padd proxy";
          p.setAttribute("data-for", i.value);
          if (t.getAttribute("data-level")) p.setAttribute("data-level", t.getAttribute("data-level"));
          p.title = t.title;
          t.childNodes.forEach(function (n) { p.appendChild(n.cloneNode(true)); });
          p.appendChild(span("x"));
          place(row, p);
        } else if (!i.checked && p) {
          p.remove();
        }
      });
    });
  }
  function untickProxy(p) {
    var row = p.closest(".rrow") || (pop && pop.owner.closest(".rrow"));
    var pw = row && document.getElementById("pick-" + row.getAttribute("data-role"));
    if (!pw) return;
    pw.querySelectorAll("label.opt input.tick").forEach(function (i) {
      if (i.value === p.getAttribute("data-for") && i.checked) {
        i.checked = false;
        i.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    closeMore(false);
    var add = row.querySelector(".tok.add");
    if (add) add.focus({ preventScroll: true });
  }

  // A person added in a picker is shown on the role's row as a pending
  // addition. The address and the day are checked again by the server.
  function addPerson(box) {
    var role = box.getAttribute("data-addperson");
    var email = box.querySelector("input[type=email]"), day = box.querySelector("input[type=date]");
    var msg = box.parentNode.querySelector(".pmsg");
    function say(text, bad) {
      msg.textContent = text;
      msg.hidden = false;
      msg.classList.toggle("bad", !!bad);
    }
    var addr = email.value.trim().toLowerCase();
    if (!addr) return true;
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr) || !email.checkValidity()) {
      say(box.getAttribute("data-msg-address"), true);
      email.focus();
      return false;
    }
    if (day.validity && day.validity.badInput) {
      say(box.getAttribute("data-msg-date"), true);
      day.focus();
      return false;
    }
    if (day.value && day.min && day.value < day.min) {
      say(box.getAttribute("data-msg-past"), true);
      day.focus();
      return false;
    }
    var row = rowOf(role);
    var dup = false;
    row.querySelectorAll("input.tick[name='p." + role + "']").forEach(function (i) {
      if (i.value.split("|")[0] === addr) {
        dup = true;
        if (!i.checked) { i.checked = true; }
      }
    });
    if (!dup) {
      var t = document.createElement("label");
      t.className = "tok padd made";
      t.setAttribute("data-level", "2");
      var i = document.createElement("input");
      i.type = "checkbox";
      i.className = "tick";
      i.name = "p." + role;
      i.value = addr + "|" + day.value;
      i.checked = true;
      i.setAttribute("data-held", "0");
      t.appendChild(i);
      t.appendChild(icon("k-person"));
      t.appendChild(span("l", addr));
      t.title = addr;
      if (day.value) {
        var d = new Date(day.value + "T12:00:00").toLocaleDateString("en-AU", { day: "numeric", month: "long", year: "numeric" });
        var until = box.getAttribute("data-msg-until").replace("%s", d);
        t.appendChild(span("n", until));
        t.title += ", " + until;
      }
      t.appendChild(span("x"));
      place(row, t);
    }
    email.value = "";
    day.value = "";
    say(box.getAttribute("data-msg-pending").replace("%s", addr), false);
    email.focus();
    update();
    return true;
  }

  // The widest access of each row, from the holders it will have once the
  // changes are saved. Any role in an app admits its user paths, so the
  // user row shows the widest of all.
  function reach() {
    var src = document.querySelector("[data-reaches]");
    if (!form || !src) return;
    var rows = form.querySelectorAll(".rrow[data-role]"), levels = [], all = 0;
    rows.forEach(function (r, k) {
      var l = 0;
      r.querySelectorAll(".rwho .tok[data-level]").forEach(function (t) {
        var i = t.querySelector("input.tick");
        if (i && !i.checked) return;
        l = Math.max(l, +t.getAttribute("data-level"));
      });
      levels[k] = l;
      all = Math.max(all, l);
    });
    rows.forEach(function (r, k) {
      var l = r.getAttribute("data-role") === "user" ? all : levels[k];
      var from = src.querySelector("[data-level='" + l + "'] .reach"), cur = r.querySelector(".reach");
      if (from && cur) cur.replaceWith(from.cloneNode(true));
    });
  }

  var words = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"];
  function changed() {
    var n = 0;
    if (form) form.querySelectorAll("input.tick").forEach(function (i) {
      if (i.checked !== (i.getAttribute("data-held") === "1")) n++;
    });
    return n;
  }
  function count() {
    if (!form) return;
    var n = changed();
    var bar = form.querySelector(".changes");
    bar.querySelector("[data-none]").hidden = n > 0;
    var some = bar.querySelector("[data-some]");
    some.hidden = n === 0;
    some.textContent = (words[n] || String(n)) + (n === 1 ? " change has" : " changes have") + " not been saved.";
    bar.querySelector("[data-discard]").hidden = n === 0;
    bar.className = "changes " + (n ? "some" : "none");
  }
  function update() { syncPicks(); count(); reach(); fit(); }

  var opener = null;
  function picker() {
    var h = location.hash;
    var p = h.indexOf("#pick-") === 0 ? document.getElementById(h.slice(1)) : null;
    lift(null);
    if (p) {
      opener = document.querySelector("a.tok.add[href='" + h + "']");
      var msg = p.querySelector(".pmsg");
      if (msg) msg.hidden = true;
      lift(p);
      var first = p.querySelector("input.tick, .addperson input, a[data-close]");
      (first || p).focus({ preventScroll: true });
    } else if (opener) {
      opener.focus({ preventScroll: true });
      opener = null;
    }
  }
  // An open picker hangs under its role's row, and the row stays above the
  // shade, so each change shows on the row as it is made. The picker never
  // reaches up under the row: a picker taller than the room below the row
  // scrolls within itself, and one with too little room opens at the top
  // of the shade, over the row, as it does without the script.
  function lift(pw) {
    document.querySelectorAll(".rrow.lift").forEach(function (r) { r.classList.remove("lift"); });
    if (!pw) return;
    var row = rowOf(pw.id.slice(5)), pop = pw.querySelector(".pop");
    if (!row || !pop) return;
    pw.style.paddingTop = pw.style.paddingLeft = pw.style.justifyContent = pop.style.maxHeight = "";
    var r = row.getBoundingClientRect(), need = r.bottom + 8 + pop.offsetHeight + 16;
    if (need > innerHeight && r.top > 64) {
      scrollBy(0, Math.min(r.top - 64, need - innerHeight));
      r = row.getBoundingClientRect();
    }
    var top = Math.max(16, r.bottom + 8), room = innerHeight - top - 16;
    if (room < 160) return;
    row.classList.add("lift");
    pw.scrollTop = 0;
    pw.style.paddingTop = top + "px";
    pop.style.maxHeight = room + "px";
    var who = row.querySelector(".rwho").getBoundingClientRect();
    pw.style.justifyContent = "flex-start";
    pw.style.paddingLeft = Math.max(16, Math.min(who.left, innerWidth - pop.offsetWidth - 16)) + "px";
  }
  // Closing a picker adds a person whose address has been typed but not
  // added, and keeps the page where it was.
  function closePicker(pw) {
    var box = pw.querySelector("[data-addperson]");
    if (box && !addPerson(box)) return;
    var y = scrollY;
    location.hash = "roles";
    scrollTo(scrollX, y);
  }
  addEventListener("resize", function () {
    fit();
    if (location.hash.indexOf("#pick-") === 0) lift(document.getElementById(location.hash.slice(1)));
  });
  addEventListener("hashchange", picker);
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!t.classList || !t.classList.contains("tick")) return;
    var made = t.closest(".tok.made");
    if (made && !t.checked) made.remove();
    update();
  });
  document.addEventListener("click", function (e) {
    var t = e.target;
    var m = t.closest && t.closest(".tok.more");
    var px = t.closest && t.closest(".tok.proxy");
    var close = t.closest && t.closest(".pickwrap a[data-close], .pickwrap a.away");
    var add = t.closest && t.closest("[data-addperson] button");
    if (m) {
      e.preventDefault();
      if (pop && pop.owner === m) closeMore(true); else openMore(m);
      return;
    }
    if (pop && !pop.contains(t)) closeMore(false);
    if (px && !(pop && pop.contains(px))) {
      e.preventDefault();
      untickProxy(px);
    } else if (close) {
      e.preventDefault();
      closePicker(close.closest(".pickwrap"));
    } else if (add) {
      e.preventDefault();
      addPerson(add.closest("[data-addperson]"));
    }
  });
  document.addEventListener("keydown", function (e) {
    var box = e.target.closest && e.target.closest("[data-addperson]");
    if (box && e.key === "Enter") {
      e.preventDefault();
      addPerson(box);
      return;
    }
    if (e.key !== "Escape") return;
    if (pop) { closeMore(true); return; }
    var pw = location.hash.indexOf("#pick-") === 0 ? document.getElementById(location.hash.slice(1)) : null;
    if (pw) closePicker(pw);
  });
  // Leaving the page with changes that have not been saved is asked about
  // first; a form's own submission and Discard are not.
  var leaving = false;
  document.addEventListener("submit", function () { leaving = true; });
  document.addEventListener("click", function (e) {
    if (e.target.closest && e.target.closest("[data-discard]")) leaving = true;
  });
  addEventListener("beforeunload", function (e) {
    if (leaving || !form) return;
    var typed = false;
    form.querySelectorAll("[data-addperson] input[type=email]").forEach(function (i) { if (i.value.trim()) typed = true; });
    if (changed() > 0 || typed) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
  update();
  picker();
})();`

// scriptHash is the CSP source that allows exactly one inline script.
func scriptHash(script string) string {
	sum := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}
