// passkey.js — the only script on the sign-in pages, loaded only when
// passkeys are enabled. It runs the browser's passkey ceremony and posts the
// result in an ordinary form; the server checks everything. It reads its
// options from data attributes, writes no markup, and makes no requests of
// its own. All wording lives in the page templates.
(function () {
  'use strict';

  function enc(buf) {
    var bytes = new Uint8Array(buf), s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function dec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function byId(id) { return document.getElementById(id); }
  function set(form, name, value) { form.elements[name].value = value; }
  function show(el) { if (el) el.hidden = false; }
  function supported() { return !!(window.PublicKeyCredential && navigator.credentials); }
  function isPhone() {
    if (navigator.userAgentData && typeof navigator.userAgentData.mobile === 'boolean') {
      return navigator.userAgentData.mobile;
    }
    return /iPhone|Android.+Mobile/.test(navigator.userAgent);
  }
  function platformAvailable() {
    if (!supported() || !PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      return Promise.resolve(false);
    }
    return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(function () { return false; });
  }
  // A person who cancels the phone's check has not had an error.
  function failed(err) {
    if (err && (err.name === 'NotAllowedError' || err.name === 'AbortError')) return;
    show(byId('passkey-error'));
  }

  // --- Signing in ---
  var login = byId('passkey-login');
  if (login && supported()) {
    var pending = null;
    var get = function (mediation) {
      if (pending) pending.abort();
      pending = new AbortController();
      var opts = {
        publicKey: {
          challenge: dec(login.dataset.challenge),
          rpId: login.dataset.rpid,
          userVerification: 'required',
          timeout: 300000
        },
        signal: pending.signal
      };
      if (mediation) opts.mediation = mediation;
      return navigator.credentials.get(opts).then(function (cred) {
        if (!cred) return;
        var r = cred.response;
        set(login, 'id', enc(cred.rawId));
        set(login, 'clientDataJSON', enc(r.clientDataJSON));
        set(login, 'authenticatorData', enc(r.authenticatorData));
        set(login, 'signature', enc(r.signature));
        set(login, 'userHandle', r.userHandle ? enc(r.userHandle) : '');
        var remember = document.querySelector('input[type=checkbox][name=remember]');
        set(login, 'remember', remember && remember.checked ? '1' : '');
        login.submit();
      });
    };
    var conditional = function () {
      if (!PublicKeyCredential.isConditionalMediationAvailable) return;
      PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
        if (ok) get('conditional').catch(function () {});
      });
    };
    conditional();
    var button = byId('passkey-button');
    if (button && isPhone()) {
      platformAvailable().then(function (ok) { if (ok) show(byId('passkey-button-wrap')); });
      button.addEventListener('click', function () {
        get().catch(function (err) { failed(err); conditional(); });
      });
    }
  }

  // --- Adding a passkey ---
  var reg = byId('passkey-register');
  if (reg) {
    var skip = byId('passkey-skip');
    platformAvailable().then(function (ok) {
      if (ok) {
        show(byId('passkey-add-wrap'));
      } else if (skip) {
        // Nothing to offer on this browser: go straight on.
        window.location.replace(skip.href);
      }
    });
    var create = function () {
      var d = reg.dataset;
      var exclude = (d.exclude || '').split(',').filter(Boolean).map(function (id) {
        return { type: 'public-key', id: dec(id) };
      });
      return navigator.credentials.create({
        publicKey: {
          challenge: dec(d.challenge),
          rp: { id: d.rpid, name: d.rpname },
          user: { id: dec(d.userid), name: d.username, displayName: d.username },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            residentKey: 'required',
            requireResidentKey: true,
            userVerification: 'required'
          },
          attestation: 'none',
          excludeCredentials: exclude,
          timeout: 300000
        }
      }).then(function (cred) {
        var r = cred.response;
        if (!r.getPublicKey || !r.getAuthenticatorData || !r.getPublicKey()) {
          throw new Error('unsupported');
        }
        set(reg, 'id', enc(cred.rawId));
        set(reg, 'clientDataJSON', enc(r.clientDataJSON));
        set(reg, 'authenticatorData', enc(r.getAuthenticatorData()));
        set(reg, 'publicKey', enc(r.getPublicKey()));
        set(reg, 'publicKeyAlg', String(r.getPublicKeyAlgorithm()));
        reg.submit();
      });
    };
    if (reg.dataset.confirm === '1') {
      // The administrator's code is posted with the new passkey.
      reg.addEventListener('submit', function (e) {
        e.preventDefault();
        if (!reg.reportValidity()) return;
        create().catch(failed);
      });
    } else {
      var add = byId('passkey-add');
      if (add) add.addEventListener('click', function () { create().catch(failed); });
    }
  }
})();
