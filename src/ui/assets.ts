/* Inline assets for the local pages. Served with a per-response CSP nonce. */

export const CSS = String.raw`
:root {
  --bg: #f6f7f9; --surface: #ffffff; --text: #16181d; --muted: #5b6270; --border: #d5d9e0;
  --accent: #1f5fd1; --accent-text: #ffffff; --danger: #b42318; --danger-bg: #fdecea;
  --ok: #157f3d; --ok-bg: #e8f6ee; --warn-bg: #fff6e0; --warn: #8a5a00; --focus: #1f5fd1; --code-bg: #eef1f5;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1115; --surface: #171a21; --text: #e8eaef; --muted: #a2a9b6; --border: #2c323d;
    --accent: #6d9cff; --accent-text: #0b0d12; --danger: #ff8b80; --danger-bg: #3a1714;
    --ok: #6fd69a; --ok-bg: #12301f; --warn-bg: #33270a; --warn: #f5c869; --focus: #8fb3ff; --code-bg: #10131a;
  }
}
* { box-sizing: border-box; }
html { font-size: 16px; }
body { margin: 0; background: var(--bg); color: var(--text); font: 1rem/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 880px; margin: 0 auto; padding: 24px 16px 64px; }
header.si { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.brand { font-weight: 600; letter-spacing: .01em; }
.lang { color: var(--accent); }
.notice { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--ok); border-radius: 8px; padding: 10px 14px; color: var(--muted); font-size: .9rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-top: 16px; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 0 0 8px; }
.desc { color: var(--muted); white-space: pre-wrap; margin: 4px 0 0; }
.meta { color: var(--muted); font-size: .85rem; }
fieldset { border: 0; padding: 0; margin: 0 0 8px; min-width: 0; }
fieldset.section { border-top: 1px solid var(--border); padding-top: 16px; margin-top: 16px; }
legend { font-weight: 600; font-size: 1.05rem; padding: 0; margin-bottom: 4px; }
.field { margin: 14px 0; }
.field > label, .field > .label { display: block; font-weight: 600; margin-bottom: 4px; }
.req { color: var(--danger); font-weight: 400; font-size: .85rem; margin-left: 6px; }
.opt { color: var(--muted); font-weight: 400; font-size: .85rem; margin-left: 6px; }
.help { color: var(--muted); font-size: .88rem; margin-top: 4px; white-space: pre-wrap; }
.error { color: var(--danger); font-size: .88rem; margin-top: 4px; }
.error:empty { display: none; }
input[type=text], input[type=password], input[type=date], select, textarea {
  width: 100%; padding: 9px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); color: var(--text); font: inherit;
}
textarea { min-height: 110px; resize: vertical; }
input[aria-invalid=true], select[aria-invalid=true], textarea[aria-invalid=true] { border-color: var(--danger); }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.secret-wrap, .money-wrap { display: flex; gap: 8px; }
.secret-wrap input { flex: 1; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.money-wrap input { flex: 1; }
.money-wrap select { width: auto; }
.money-wrap .cur { align-self: center; color: var(--muted); }
button { font: inherit; border-radius: 8px; padding: 9px 16px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); font-weight: 600; }
button.danger { color: var(--danger); }
button:disabled { opacity: .55; cursor: not-allowed; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 20px; }
.check { display: flex; gap: 8px; align-items: flex-start; margin: 6px 0; }
.check input { margin-top: 4px; width: 18px; height: 18px; }
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 6px 8px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { font-size: .85rem; color: var(--muted); font-weight: 600; white-space: nowrap; }
td input[type=text], td input[type=password], td select { min-width: 120px; }
.repeater-tools { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 8px; }
.paste { margin-top: 8px; }
.dest { background: var(--warn-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; margin-top: 16px; }
.dest dt { font-weight: 600; font-size: .85rem; color: var(--warn); }
.dest dd { margin: 0 0 8px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .88rem; white-space: pre-wrap; word-break: break-word; }
pre.literal { background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-size: .9rem; }
.warnings { background: var(--danger-bg); color: var(--danger); border-radius: 8px; padding: 10px 14px; margin-top: 12px; }
.status { border-radius: 8px; padding: 12px 14px; margin-top: 16px; }
.status.ok { background: var(--ok-bg); color: var(--ok); }
.status.err { background: var(--danger-bg); color: var(--danger); }
.banner { background: var(--warn-bg); color: var(--warn); border-radius: 8px; padding: 10px 14px; margin-top: 12px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
[hidden] { display: none !important; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
@media (max-width: 560px) { .card { padding: 14px; } h1 { font-size: 1.3rem; } }
`;

/**
 * Client script. Renders the form from the JSON schema using DOM APIs only
 * (textContent, never innerHTML), so model-provided labels cannot inject markup.
 * Values are POSTed to this same origin with the CSRF token; nothing else.
 */
export const CLIENT_JS = String.raw`
(function () {
  'use strict';
  var data = JSON.parse(document.getElementById('si-data').textContent);
  var T = data.strings;
  var root = document.getElementById('app');
  var fileCache = {};
  var uid = 0;

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
      var v = attrs[k];
      if (v === undefined || v === null || v === false) continue;
      if (k === 'text') e.textContent = String(v);
      else if (k === 'class') e.className = v;
      else if (k === 'on') { for (var ev in v) e.addEventListener(ev, v[ev]); }
      else e.setAttribute(k, v === true ? '' : String(v));
    }
    (children || []).forEach(function (c) { if (c) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return e;
  }
  function fmt(s, n) { return String(s).replace('{n}', String(n)); }
  function nid(p) { uid += 1; return 'f' + uid + '-' + p.replace(/[^A-Za-z0-9_-]/g, '_'); }
  var NOFILL = { autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', autocorrect: 'off', 'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other' };
  function noFill(a) { var o = {}; for (var k in NOFILL) o[k] = NOFILL[k]; for (var j in a) o[j] = a[j]; return o; }
  function optVal(o) { return typeof o === 'string' ? o : o.value; }
  function optLabel(o) { return typeof o === 'string' ? o : o.label; }

  // ---------------------------------------------------------------- inputs
  function buildInput(f, path, disabled) {
    var id = nid(path);
    var helpId = id + '-help', errId = id + '-err';
    var described = (f.help ? helpId + ' ' : '') + errId;
    var wrap = el('div', { class: 'field', 'data-path': path, 'data-name': f.name });
    var reqMark = f.required ? el('span', { class: 'req', text: '(' + T.required + ')' }) : null;
    var control, getter;
    var common = noFill({ id: id, name: path, 'aria-describedby': described, required: f.required ? true : null, disabled: disabled ? true : null, placeholder: f.placeholder });
    switch (f.kind) {
      case 'secret': {
        var inp = el('input', Object.assign({}, common, { type: 'password', autocomplete: 'new-password', maxlength: f.maxLength }));
        var tog = el('button', { type: 'button', class: 'toggle', 'aria-pressed': 'false', 'aria-controls': id, text: T.show, disabled: disabled ? true : null });
        tog.addEventListener('click', function () {
          var shown = inp.type === 'text';
          inp.type = shown ? 'password' : 'text';
          tog.textContent = shown ? T.show : T.hide;
          tog.setAttribute('aria-pressed', shown ? 'false' : 'true');
        });
        control = el('div', { class: 'secret-wrap' }, [inp, tog]);
        getter = function () { return inp.value; };
        control.focusTarget = inp;
        break;
      }
      case 'textarea': {
        var ta = el('textarea', Object.assign({}, common, { maxlength: f.maxLength }));
        if (f.default !== undefined) ta.value = String(f.default);
        control = ta; getter = function () { return ta.value; };
        break;
      }
      case 'number': {
        var ni = el('input', Object.assign({}, common, { type: 'text', inputmode: 'decimal' }));
        if (f.default !== undefined) ni.value = String(f.default);
        control = ni; getter = function () { return ni.value; };
        break;
      }
      case 'money': {
        var ai = el('input', Object.assign({}, common, { type: 'text', inputmode: 'decimal' }));
        if (f.default !== undefined) ai.value = String(f.default);
        var curs = f.currencies || [f.currency || 'USD'];
        var cur;
        if (curs.length > 1) {
          cur = el('select', { 'aria-label': f.label + ' (currency)', disabled: disabled ? true : null }, curs.map(function (c) { return el('option', { value: c, text: c }); }));
        } else cur = el('span', { class: 'cur', text: curs[0] });
        control = el('div', { class: 'money-wrap' }, [ai, cur]);
        control.focusTarget = ai;
        getter = function () { return { amount: ai.value, currency: cur.tagName === 'SELECT' ? cur.value : curs[0] }; };
        break;
      }
      case 'date': {
        var di = el('input', Object.assign({}, common, { type: 'date' }));
        if (f.default !== undefined) di.value = String(f.default);
        control = di; getter = function () { return di.value; };
        break;
      }
      case 'select': {
        var sel = el('select', common, [el('option', { value: '', text: '—' })].concat((f.options || []).map(function (o) { return el('option', { value: optVal(o), text: optLabel(o) }); })));
        if (f.default !== undefined) sel.value = String(f.default);
        control = sel; getter = function () { return sel.value; };
        break;
      }
      case 'multiselect': {
        var boxes = [];
        var fs = el('fieldset', { id: id, 'aria-describedby': described }, [el('legend', { class: 'sr-only', text: f.label })].concat((f.options || []).map(function (o) {
          var cid = nid(path + '-' + optVal(o));
          var cb = el('input', { type: 'checkbox', id: cid, value: optVal(o), disabled: disabled ? true : null });
          boxes.push(cb);
          return el('div', { class: 'check' }, [cb, el('label', { for: cid, text: optLabel(o) })]);
        })));
        control = fs; getter = function () { return boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; }); };
        control.focusTarget = boxes[0];
        break;
      }
      case 'boolean': {
        var cbx = el('input', Object.assign({}, common, { type: 'checkbox', required: null }));
        if (f.default === true) cbx.checked = true;
        getter = function () { return cbx.checked; };
        wrap.appendChild(el('div', { class: 'check' }, [cbx, el('label', { for: id }, [f.label, reqMark])]));
        if (f.help) wrap.appendChild(el('div', { class: 'help', id: helpId, text: f.help }));
        wrap.appendChild(el('div', { class: 'error', id: errId, 'aria-live': 'polite' }));
        wrap.getValue = getter; wrap.focusTarget = cbx; wrap.errEl = wrap.lastChild;
        return wrap;
      }
      case 'file': {
        var fi = el('input', Object.assign({}, common, { type: 'file', accept: (f.accept || []).join(',') || null }));
        fi.addEventListener('change', function () {
          var file = fi.files && fi.files[0];
          if (!file) { delete fileCache[path]; return; }
          var rd = new FileReader();
          rd.onload = function () { var s = String(rd.result); fileCache[path] = { name: file.name, type: file.type, b64: s.slice(s.indexOf(',') + 1) }; };
          rd.readAsDataURL(file);
        });
        control = fi; getter = function () { return fileCache[path] || null; };
        break;
      }
      default: {
        var ti = el('input', Object.assign({}, common, { type: 'text', maxlength: f.maxLength, pattern: f.pattern || null }));
        if (f.default !== undefined) ti.value = String(f.default);
        control = ti; getter = function () { return ti.value; };
      }
    }
    var label = f.kind === 'multiselect' ? el('div', { class: 'label', id: id + '-label' }, [f.label, reqMark]) : el('label', { for: id }, [f.label, reqMark]);
    wrap.appendChild(label);
    wrap.appendChild(control);
    if (f.help) wrap.appendChild(el('div', { class: 'help', id: helpId, text: f.help }));
    var err = el('div', { class: 'error', id: errId, 'aria-live': 'polite' });
    wrap.appendChild(err);
    wrap.getValue = getter; wrap.focusTarget = control.focusTarget || control; wrap.errEl = err;
    return wrap;
  }

  // ---------------------------------------------------------------- repeater
  function parseDelimited(text) {
    var delim = text.indexOf('\t') >= 0 ? '\t' : (text.indexOf(';') >= 0 && text.indexOf(',') < 0 ? ';' : ',');
    var rows = [], row = [], cell = '', q = false;
    for (var i = 0; i < text.length; i++) {
      var c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; }
        else cell += c;
      } else if (c === '"' && cell === '') q = true;
      else if (c === delim) { row.push(cell); cell = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(cell); cell = '';
        if (row.some(function (x) { return x !== ''; })) rows.push(row);
        row = [];
      } else cell += c;
    }
    row.push(cell);
    if (row.some(function (x) { return x !== ''; })) rows.push(row);
    return rows;
  }

  function buildRepeater(f, disabled) {
    var id = nid(f.name);
    var wrap = el('div', { class: 'field repeater', 'data-path': f.name, 'data-name': f.name });
    var reqMark = (f.required || f.minRows) ? el('span', { class: 'req', text: '(' + T.required + ')' }) : null;
    wrap.appendChild(el('div', { class: 'label', id: id + '-label' }, [f.label, reqMark]));
    if (f.help) wrap.appendChild(el('div', { class: 'help', text: f.help }));
    var cols = f.fields || [];
    var tbody = el('tbody');
    var table = el('table', { 'aria-labelledby': id + '-label' }, [
      el('thead', null, [el('tr', null, [el('th', { scope: 'col', text: '#' })].concat(cols.map(function (c) { return el('th', { scope: 'col' }, [c.label, c.required ? el('span', { class: 'req', text: '*' }) : null]); })).concat([el('th', { scope: 'col' }, [el('span', { class: 'sr-only', text: T.removeRow })])]))]),
      tbody,
    ]);
    var rows = [];
    var count = el('span', { class: 'meta', 'aria-live': 'polite' });
    function renumber() {
      rows.forEach(function (r, i) { r.num.textContent = String(i + 1); r.index = i; });
      count.textContent = rows.length + ' ' + T.rows;
    }
    function addRow(vals) {
      var r = { cells: {} };
      var tr = el('tr');
      r.num = el('td', { text: String(rows.length + 1) });
      tr.appendChild(r.num);
      cols.forEach(function (c) {
        var cellField = buildInput(Object.assign({}, c, { help: undefined }), f.name + '[' + rows.length + '].' + c.name, disabled);
        var lbl = cellField.querySelector('label, .label');
        if (lbl) lbl.className = 'sr-only';
        r.cells[c.name] = cellField;
        if (vals && vals[c.name] !== undefined) setVal(cellField, c, vals[c.name]);
        tr.appendChild(el('td', null, [cellField]));
      });
      var rm = el('button', { type: 'button', class: 'danger', 'aria-label': T.removeRow, text: '×', disabled: disabled ? true : null });
      rm.addEventListener('click', function () { tbody.removeChild(tr); rows.splice(rows.indexOf(r), 1); renumber(); });
      tr.appendChild(el('td', null, [rm]));
      r.tr = tr;
      rows.push(r);
      tbody.appendChild(tr);
      renumber();
      applyConditions();
      return r;
    }
    function setVal(cellField, c, v) {
      var t = cellField.focusTarget;
      if (!t) return;
      if (c.kind === 'boolean') t.checked = /^(1|true|yes|si|sí|x)$/i.test(String(v).trim());
      else if (c.kind === 'select') {
        var match = (c.options || []).filter(function (o) { return optVal(o).toLowerCase() === String(v).trim().toLowerCase() || optLabel(o).toLowerCase() === String(v).trim().toLowerCase(); })[0];
        t.value = match ? optVal(match) : '';
      } else t.value = String(v).trim();
    }
    function importText(text) {
      var data = parseDelimited(text);
      if (!data.length) return 0;
      var head = data[0].map(function (h) { return h.trim().toLowerCase(); });
      var map = cols.map(function (c) {
        var i = head.indexOf(c.name.toLowerCase());
        if (i < 0) i = head.indexOf(c.label.toLowerCase());
        return i;
      });
      var hasHeader = map.some(function (i) { return i >= 0; });
      if (!hasHeader) map = cols.map(function (_c, i) { return i; });
      var body = hasHeader ? data.slice(1) : data;
      // drop the single empty starter row
      if (rows.length === 1 && cols.every(function (c) { var v = rows[0].cells[c.name].getValue(); return v === '' || v === false || v === null || (v && v.amount === ''); })) { tbody.removeChild(rows[0].tr); rows.splice(0, 1); }
      body.forEach(function (line) {
        var vals = {};
        cols.forEach(function (c, ci) { if (map[ci] >= 0 && line[map[ci]] !== undefined) vals[c.name] = line[map[ci]]; });
        addRow(vals);
      });
      return body.length;
    }
    wrap.appendChild(el('div', { class: 'table-wrap' }, [table]));
    var tools = el('div', { class: 'repeater-tools' });
    tools.appendChild(el('button', { type: 'button', text: T.addRow, disabled: disabled ? true : null, on: { click: function () { var r = addRow(); var first = r.cells[cols[0].name]; if (first && first.focusTarget) first.focusTarget.focus(); } } }));
    tools.appendChild(count);
    wrap.appendChild(tools);
    if (f.csv !== false) {
      var status = el('div', { class: 'meta', 'aria-live': 'polite' });
      var csvId = nid(f.name + '-csv');
      var csvIn = el('input', { type: 'file', id: csvId, accept: '.csv,.tsv,text/csv,text/tab-separated-values,text/plain', disabled: disabled ? true : null });
      csvIn.addEventListener('change', function () {
        var file = csvIn.files && csvIn.files[0];
        if (!file) return;
        file.text().then(function (txt) { status.textContent = fmt(T.importedRows, importText(txt)); csvIn.value = ''; });
      });
      var pasteId = nid(f.name + '-paste');
      var paste = el('textarea', noFill({ id: pasteId, rows: '3', disabled: disabled ? true : null }));
      var pasteBtn = el('button', { type: 'button', text: T.pasteButton, disabled: disabled ? true : null, on: { click: function () { status.textContent = fmt(T.importedRows, importText(paste.value)); paste.value = ''; } } });
      wrap.appendChild(el('div', { class: 'paste' }, [
        el('label', { for: csvId, text: T.importCsv }), csvIn,
        el('div', { class: 'field' }, [el('label', { for: pasteId, text: T.pasteLabel }), paste]),
        pasteBtn, status,
      ]));
    }
    var err = el('div', { class: 'error', 'aria-live': 'polite' });
    wrap.appendChild(err);
    wrap.errEl = err;
    wrap.focusTarget = tools.firstChild;
    wrap.rows = rows;
    wrap.cols = cols;
    wrap.getValue = function () {
      return rows.map(function (r) { var o = {}; cols.forEach(function (c) { if (!r.cells[c.name].hidden) o[c.name] = r.cells[c.name].getValue(); }); return o; });
    };
    var initial = Math.max(1, f.minRows || 0);
    for (var i = 0; i < initial; i++) addRow();
    return wrap;
  }

  // ---------------------------------------------------------------- conditions
  var fieldEls = {};
  function scalar(v) { return v && typeof v === 'object' && !Array.isArray(v) && 'amount' in v ? v.amount : v; }
  function holds(cond, scope) {
    if (!cond) return true;
    var v = scalar(scope(cond.field));
    var empty = v === undefined || v === null || v === '' || v === false || (Array.isArray(v) && !v.length);
    if (cond.notEmpty !== undefined) return cond.notEmpty ? !empty : empty;
    if (cond.in) return Array.isArray(v) ? v.some(function (x) { return cond.in.indexOf(String(x)) >= 0; }) : cond.in.indexOf(String(v === undefined || v === null ? '' : v)) >= 0;
    if (cond.equals !== undefined) {
      if (typeof cond.equals === 'boolean') return (v === true || v === 'true') === cond.equals;
      return String(v === undefined || v === null ? '' : v) === String(cond.equals);
    }
    return !empty;
  }
  function setHidden(node, hidden) {
    node.hidden = hidden;
    Array.prototype.forEach.call(node.querySelectorAll('input,select,textarea,button'), function (i) { if (!data.preview) i.disabled = hidden; });
  }
  function applyConditions() {
    var top = function (n) { return fieldEls[n] ? fieldEls[n].getValue() : undefined; };
    data.schema.sections.forEach(function (s) {
      s.fields.forEach(function (f) {
        var node = fieldEls[f.name];
        if (!node) return;
        if (f.showIf) setHidden(node, !holds(f.showIf, top));
        if (f.kind === 'repeater' && node.rows) {
          node.rows.forEach(function (r) {
            (f.fields || []).forEach(function (c) {
              if (!c.showIf) return;
              var cell = r.cells[c.name];
              setHidden(cell, !holds(c.showIf, function (n) { return r.cells[n] ? r.cells[n].getValue() : undefined; }));
            });
          });
        }
      });
    });
  }

  // ---------------------------------------------------------------- client validation
  function clientErrors() {
    var errs = [];
    data.schema.sections.forEach(function (s) {
      s.fields.forEach(function (f) {
        var node = fieldEls[f.name];
        if (!node || node.hidden) return;
        if (f.kind === 'repeater') {
          node.rows.forEach(function (r, i) {
            var any = f.fields.some(function (c) { var v = scalar(r.cells[c.name].getValue()); return v !== '' && v !== false && v !== null && v !== undefined; });
            if (!any) return;
            f.fields.forEach(function (c) {
              if (r.cells[c.name].hidden) return;
              var code = check(c, r.cells[c.name].getValue());
              if (code) errs.push({ field: f.name + '[' + i + '].' + c.name, code: code });
            });
          });
          return;
        }
        var code = check(f, node.getValue());
        if (code) errs.push({ field: f.name, code: code });
      });
    });
    return errs;
  }
  function check(f, v) {
    var sv = scalar(v);
    var empty = sv === '' || sv === null || sv === undefined || (Array.isArray(sv) && !sv.length) || (f.kind === 'boolean' && sv === false);
    if (empty) return f.required ? 'required' : null;
    if ((f.kind === 'text' || f.kind === 'secret' || f.kind === 'textarea') && f.pattern) {
      try { if (!new RegExp('^(?:' + f.pattern + ')$', 'u').test(sv)) return 'pattern'; } catch (e) { return null; }
    }
    if (f.kind === 'number' || f.kind === 'money') {
      var s = String(sv).replace(/[\s_]/g, '');
      if (/^-?\d{1,3}(,\d{3})+(\.\d+)?$/.test(s)) s = s.replace(/,/g, ''); else if (/^-?\d+,\d+$/.test(s)) s = s.replace(',', '.');
      if (!/^-?\d+(\.\d+)?$/.test(s)) return 'type';
      var n = Number(s);
      if (f.min !== undefined && n < f.min) return 'min';
      if (f.max !== undefined && n > f.max) return 'max';
    }
    if (f.minLength !== undefined && String(sv).length < f.minLength) return 'min_length';
    return null;
  }

  function nodeForPath(p) {
    var m = /^([A-Za-z0-9_]+)\[(\d+)\]\.([A-Za-z0-9_]+)$/.exec(p);
    if (m) { var rep = fieldEls[m[1]]; var r = rep && rep.rows[Number(m[2])]; return r ? r.cells[m[3]] : rep; }
    return fieldEls[p];
  }
  function clearErrors() {
    Array.prototype.forEach.call(root.querySelectorAll('.error'), function (e) { e.textContent = ''; });
    Array.prototype.forEach.call(root.querySelectorAll('[aria-invalid]'), function (e) { e.removeAttribute('aria-invalid'); });
  }
  function showErrors(errs) {
    clearErrors();
    var first = null;
    errs.forEach(function (er) {
      var node = er.field === '__confirm' ? confirmNode : nodeForPath(er.field);
      if (!node) return;
      node.errEl.textContent = T['err_' + er.code] || T.err_type;
      if (node.focusTarget && node.focusTarget.setAttribute) node.focusTarget.setAttribute('aria-invalid', 'true');
      if (!first) first = node;
    });
    statusEl.className = 'status err';
    statusEl.textContent = T.errorSummary;
    if (first && first.focusTarget && first.focusTarget.focus) first.focusTarget.focus();
  }

  // ---------------------------------------------------------------- render
  var statusEl = el('div', { role: 'status', 'aria-live': 'polite' });
  var confirmNode = null;

  function post(body) {
    return fetch(data.action, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-SI-CSRF': data.csrf },
      body: JSON.stringify(Object.assign({ csrf: data.csrf }, body)),
    }).then(function (r) { return r.json(); });
  }

  function finish(message, ok) {
    root.textContent = '';
    root.appendChild(el('div', { class: 'card' }, [el('div', { class: 'status ' + (ok ? 'ok' : 'err'), role: 'status', text: message })]));
    fileCache = {};
  }

  function destinationBox() {
    if (!data.destination) return null;
    var dl = el('dl');
    data.destination.lines.forEach(function (l) { dl.appendChild(el('dt', { text: l.label })); dl.appendChild(el('dd', { text: l.value })); });
    var box = el('section', { class: 'dest', 'aria-labelledby': 'dest-h' }, [el('h2', { id: 'dest-h', text: T.destinationTitle }), dl]);
    if (data.destination.needsConfirm) {
      var c1 = el('input', { type: 'checkbox', id: 'si-confirm' });
      var errC = el('div', { class: 'error', 'aria-live': 'polite' });
      box.appendChild(el('div', { class: 'check' }, [c1, el('label', { for: 'si-confirm', text: T.confirmDestination })]));
      box.appendChild(errC);
      confirmNode = { focusTarget: c1, errEl: errC, input: c1 };
      if (data.destination.rememberable) {
        var c2 = el('input', { type: 'checkbox', id: 'si-remember' });
        box.appendChild(el('div', { class: 'check' }, [c2, el('label', { for: 'si-remember', text: T.remember })]));
        confirmNode.remember = c2;
      }
    }
    return box;
  }

  function renderForm() {
    var form = el('form', { novalidate: true, autocomplete: 'off' });
    data.schema.sections.forEach(function (s, si) {
      var fs = el('fieldset', { class: si ? 'section' : '' });
      if (s.title) fs.appendChild(el('legend', { text: s.title }));
      if (s.description) fs.appendChild(el('p', { class: 'desc', text: s.description }));
      s.fields.forEach(function (f) {
        var node = f.kind === 'repeater' ? buildRepeater(f, data.preview) : buildInput(f, f.name, data.preview);
        fieldEls[f.name] = node;
        fs.appendChild(node);
      });
      form.appendChild(fs);
    });
    form.addEventListener('input', applyConditions);
    form.addEventListener('change', applyConditions);
    var dest = destinationBox();
    if (dest) form.appendChild(dest);
    var submit = el('button', { type: 'submit', class: 'primary', text: data.submitLabel || T.submit, disabled: data.preview ? true : null });
    var cancel = el('button', { type: 'button', text: T.cancel, disabled: data.preview ? true : null });
    form.appendChild(el('div', { class: 'actions' }, [submit, cancel]));
    form.appendChild(statusEl);
    cancel.addEventListener('click', function () {
      post({ action: 'cancel' }).then(function () { finish(T.cancelled, false); }, function () { finish(T.networkError, false); });
    });
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (data.preview) return;
      var errs = clientErrors();
      if (confirmNode && !confirmNode.input.checked) errs.push({ field: '__confirm', code: 'confirm' });
      if (errs.length) { showErrors(errs); return; }
      var values = {};
      Object.keys(fieldEls).forEach(function (k) { if (!fieldEls[k].hidden) values[k] = fieldEls[k].getValue(); });
      submit.disabled = true;
      post({ action: 'submit', values: values, confirm: confirmNode ? confirmNode.input.checked : undefined, remember: confirmNode && confirmNode.remember ? confirmNode.remember.checked : false })
        .then(function (res) {
          submit.disabled = false;
          if (res.ok) { values = null; finish(res.message || T.saved, true); }
          else if (res.errors) showErrors(res.errors);
          else finish(res.message || T.expired, false);
        }, function () { submit.disabled = false; statusEl.className = 'status err'; statusEl.textContent = T.networkError; });
    });
    root.appendChild(form);
    applyConditions();
  }

  function renderApproval() {
    var a = data.approval;
    var card = el('div');
    if (a.items && a.items.length) {
      var dl = el('dl', { class: 'dest' });
      a.items.forEach(function (it) { dl.appendChild(el('dt', { text: it.label })); dl.appendChild(el('dd', { text: it.value })); });
      card.appendChild(dl);
    }
    if (a.literal) {
      card.appendChild(el('h2', { text: T.literal }));
      card.appendChild(el('pre', { class: 'literal', text: a.literal }));
    }
    if (a.warnings && a.warnings.length) {
      card.appendChild(el('div', { class: 'warnings', role: 'note' }, [el('strong', { text: T.warnings })].concat([el('ul', null, a.warnings.map(function (w) { return el('li', { text: w }); }))])));
    }
    var rem = null;
    if (a.rememberable) {
      rem = el('input', { type: 'checkbox', id: 'si-remember' });
      card.appendChild(el('div', { class: 'check' }, [rem, el('label', { for: 'si-remember', text: T.rememberUse })]));
    }
    var ok = el('button', { type: 'button', class: 'primary', text: a.approveLabel || T.approve });
    var no = el('button', { type: 'button', class: 'danger', text: T.deny });
    card.appendChild(el('div', { class: 'actions' }, [ok, no]));
    card.appendChild(statusEl);
    ok.addEventListener('click', function () {
      ok.disabled = true; no.disabled = true;
      post({ action: 'approve', remember: rem ? rem.checked : false }).then(function (res) {
        if (res.clipboard) return doClipboard(res.clipboard);
        finish(res.ok ? (res.message || T.approved) : (res.message || T.expired), !!res.ok);
      }, function () { finish(T.networkError, false); });
    });
    no.addEventListener('click', function () {
      ok.disabled = true; no.disabled = true;
      post({ action: 'deny' }).then(function () { finish(T.denied, false); }, function () { finish(T.networkError, false); });
    });
    root.appendChild(card);
  }

  function doClipboard(c) {
    var v = c.value;
    navigator.clipboard.writeText(v).then(function () {
      v = null;
      var left = c.clearAfter;
      finish(fmt(T.copied, left), true);
      var msg = root.querySelector('.status');
      var t = setInterval(function () {
        left -= 1;
        if (left <= 0) {
          clearInterval(t);
          navigator.clipboard.writeText('').then(function () { msg.textContent = T.cleared; }, function () { msg.textContent = T.cleared; });
        } else msg.textContent = fmt(T.copied, left);
      }, 1000);
    }, function () { v = null; finish(T.networkError, false); });
  }

  if (data.kind === 'approval' || data.kind === 'clipboard') renderApproval();
  else renderForm();
})();
`;
