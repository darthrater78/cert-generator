// Background for the sign-in, setup and MFA pages: guilloché bands, the
// card's seal, a fresh decorative serial, and a faint `openssl x509 -text`
// readout. Everything here is decoration: the readout is fixed sample text,
// never data from the certificate store. Honors prefers-reduced-motion and
// idles while the tab is hidden.
(function () {
  'use strict';

  var root = document.documentElement;
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var dpr = Math.min(window.devicePixelRatio || 1, 2);

  function token(name, fallback) {
    return getComputedStyle(root).getPropertyValue(name).trim() || fallback;
  }
  var accent = token('--accent', '#d4a017');
  var onAccent = token('--on-accent', '#0b0b0f');

  // ---- serial: a new one per visit, like issuing a certificate ----
  var serialEl = document.querySelector('[data-serial]');
  if (serialEl && window.crypto && crypto.getRandomValues) {
    var bytes = crypto.getRandomValues(new Uint8Array(6));
    var hex = Array.prototype.map.call(bytes, function (b) {
      return b.toString(16).toUpperCase().padStart(2, '0');
    }).join(':');
    var b = document.createElement('b');
    b.textContent = hex;
    serialEl.textContent = 'Serial ';
    serialEl.appendChild(b);
    serialEl.appendChild(document.createTextNode(' · '));
  }

  // ---- seal ----
  var seal = document.querySelector('.deed-seal');
  if (seal) {
    var sx = seal.getContext('2d');
    var S = seal.width / 88;
    sx.setTransform(S, 0, 0, S, 0, 0);
    sx.fillStyle = accent;
    sx.beginPath();
    for (var i = 0; i < 48; i++) {
      var a = i / 48 * Math.PI * 2, r = i % 2 ? 40 : 43;
      sx.lineTo(44 + r * Math.cos(a), 44 + r * Math.sin(a));
    }
    sx.closePath();
    sx.fill();
    sx.strokeStyle = onAccent;
    sx.lineWidth = 0.5;
    sx.globalAlpha = 0.55;
    sx.beginPath();
    for (var t = 0; t <= Math.PI * 2 + 0.03; t += 0.03) {
      var x = 44 + 19 * Math.cos(t) + 11 * Math.cos(4 * t);
      var y = 44 + 19 * Math.sin(t) - 11 * Math.sin(4 * t);
      if (t) sx.lineTo(x, y); else sx.moveTo(x, y);
    }
    sx.stroke();
    sx.globalAlpha = 0.8;
    sx.beginPath();
    sx.arc(44, 44, 34, 0, Math.PI * 2);
    sx.stroke();
  }

  // ---- guilloché bands ----
  var cv = document.querySelector('.auth-guilloche');
  if (cv) {
    var gx = cv.getContext('2d'), w = 0, h = 0, last = 0;
    var size = function () {
      w = window.innerWidth; h = window.innerHeight;
      cv.width = w * dpr; cv.height = h * dpr;
      gx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    var band = function (y0, amp, ph) {
      for (var k = 0; k < 9; k++) {
        gx.beginPath();
        for (var x = 0; x <= w; x += 3) {
          var y = y0 + Math.sin(x / 38 + k * 0.42 + ph) * amp * Math.cos(x / 160 - ph * 0.6 + k * 0.1)
                + Math.sin(x / 11 + k) * 1.2;
          if (x) gx.lineTo(x, y); else gx.moveTo(x, y);
        }
        gx.stroke();
      }
    };
    var draw = function (ms) {
      var ph = reduce ? 0 : ms / 9000;
      gx.clearRect(0, 0, w, h);
      gx.lineWidth = 0.6;
      gx.strokeStyle = accent;
      gx.globalAlpha = 0.35;
      band(30, 14, ph);
      band(h - 30, 14, -ph);
    };
    var frame = function (ms) {
      requestAnimationFrame(frame);
      if (last && ms - last < 50) return;  // ~20 fps is plenty for this drift
      last = ms;
      draw(ms);
    };
    size();
    window.addEventListener('resize', function () { size(); draw(last); });
    if (reduce) draw(0); else requestAnimationFrame(frame);
  }

  // ---- openssl readout (one per side of the card) ----
  // [kind, text, value]: p = prompt, k = key/value, v = value line, '' = plain
  var CERTS = [
    [['p', '$ openssl x509 -in root-ca.pem -noout -text'], ['', 'Certificate:'], ['', '    Data:'],
     ['k', '        Version: ', '3 (0x2)'], ['k', '        Serial Number:', ''],
     ['v', '            4f:1a:9c:02:7e:b3:55:d0:8a:21:6c:e4:13:97:0b:ff'],
     ['k', '        Signature Algorithm: ', 'ecdsa-with-SHA384'],
     ['k', '        Issuer: ', 'CN = Homelab Root CA'], ['', '        Validity'],
     ['k', '            Not Before: ', 'Sep 29 00:00:00 2026 GMT'],
     ['k', '            Not After : ', 'Sep 28 23:59:59 2036 GMT'],
     ['k', '        Subject: ', 'CN = Homelab Root CA'], ['', '        Subject Public Key Info:'],
     ['k', '            Public Key Algorithm: ', 'id-ecPublicKey'],
     ['k', '                Public-Key: ', '(384 bit)'], ['k', '                ASN1 OID: ', 'secp384r1'],
     ['', '        X509v3 extensions:'], ['k', '            X509v3 Basic Constraints: ', 'critical'],
     ['v', '                CA:TRUE'], ['k', '            X509v3 Key Usage: ', 'critical'],
     ['v', '                Certificate Sign, CRL Sign']],
    [['p', '$ openssl x509 -in nas.home.arpa.pem -noout -text'], ['', 'Certificate:'], ['', '    Data:'],
     ['k', '        Version: ', '3 (0x2)'], ['k', '        Serial Number:', ''],
     ['v', '            2b:e0:71:c9:14:0a:9f:36'],
     ['k', '        Signature Algorithm: ', 'ecdsa-with-SHA256'],
     ['k', '        Issuer: ', 'CN = Homelab Intermediate CA'], ['', '        Validity'],
     ['k', '            Not Before: ', 'Sep 29 00:00:00 2026 GMT'],
     ['k', '            Not After : ', 'Oct 29 00:00:00 2027 GMT'],
     ['k', '        Subject: ', 'CN = nas.home.arpa'], ['', '        Subject Public Key Info:'],
     ['k', '            Public Key Algorithm: ', 'id-ecPublicKey'], ['k', '                Public-Key: ', '(256 bit)'],
     ['', '        X509v3 extensions:'], ['k', '            X509v3 Subject Alternative Name: ', ''],
     ['v', '                DNS:nas.home.arpa, DNS:nas, IP Address:192.168.1.20'],
     ['k', '            X509v3 Extended Key Usage: ', ''], ['v', '                TLS Web Server Authentication']]
  ];

  // Built with DOM nodes, not innerHTML, so nothing here is ever parsed as markup.
  function span(cls, text) {
    var s = document.createElement('span');
    if (cls) s.className = cls;
    s.textContent = text;
    return s;
  }
  function renderLine(line, upto, into) {
    var full = line[1] + (line[2] || ''), text = full.slice(0, upto);
    if (line[0] === 'k') {
      into.appendChild(span('k', text.slice(0, line[1].length)));
      into.appendChild(span('v', text.slice(line[1].length)));
    } else {
      into.appendChild(span(line[0], text));
    }
  }
  function typer(pre, ci) {
    if (reduce) {
      CERTS[ci].forEach(function (line) { renderLine(line, Infinity, pre); pre.appendChild(document.createTextNode('\n')); });
      return;
    }
    var li = 0, chi = 0, partial = document.createElement('span');
    pre.appendChild(partial);
    pre.appendChild(span('cur', ''));
    function tick() {
      if (document.hidden) { setTimeout(tick, 500); return; }
      var cert = CERTS[ci], line = cert[li], full = line[1] + (line[2] || '');
      var prompt = line[0] === 'p';
      chi += prompt ? 1 : 4;
      partial.textContent = '';
      if (chi < full.length) {
        renderLine(line, chi, partial);
        setTimeout(tick, prompt ? 45 : 16);
        return;
      }
      // line complete: commit it above the partial line and cursor
      var done = document.createDocumentFragment();
      renderLine(line, full.length, done);
      done.appendChild(document.createTextNode('\n'));
      pre.insertBefore(done, partial);
      li++; chi = 0;
      if (li < cert.length) { setTimeout(tick, prompt ? 420 : 70); return; }
      li = 0; ci = (ci + 1) % CERTS.length;
      setTimeout(function () {
        while (pre.firstChild !== partial) pre.removeChild(pre.firstChild);
        tick();
      }, 3200);
    }
    tick();
  }
  Array.prototype.forEach.call(document.querySelectorAll('.auth-readout pre'), function (pre, i) {
    // stagger the second column so the two never type in lockstep
    setTimeout(function () { typer(pre, i % CERTS.length); }, reduce ? 0 : i * 1800);
  });
})();
