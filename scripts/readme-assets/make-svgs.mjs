// Generates the animated README SVGs (hero + "who sees what" diagram) and the capability icons.
//   node scripts/readme-assets/make-svgs.mjs
// Self-contained SVG: CSS keyframes only (no scripts, no external fonts), light/dark via
// prefers-color-scheme, static final frame under prefers-reduced-motion. Safe to embed as <img>.
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const OUT = path.resolve(import.meta.dirname, '../../docs/assets');
mkdirSync(path.join(OUT, 'icons'), { recursive: true });

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const pct = (t, total) => `${+((t / total) * 100).toFixed(3)}%`;

/** Keyframes from [[seconds, css]] stops on a loop of `total` seconds. */
function kf(name, total, stops) {
  return `@keyframes ${name}{${stops.map(([t, css]) => `${pct(t, total)}{${css}}`).join('')}}`;
}

const SANS = `system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif`;
const MONO = `ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace`;

// Palette: GitHub-like neutrals; text pairs checked for WCAG AA (>= 4.5:1) on their surfaces.
const THEME = `
svg{--bg:#ffffff;--panel:#f6f8fa;--edge:#d0d7de;--text:#1f2328;--muted:#59636e;--accent:#0969da;--accentText:#ffffff;
--ok:#1a7f37;--okBg:#dafbe1;--warn:#9a6700;--warnBg:#fff8c5;--bad:#cf222e;--badBg:#ffebe9;--field:#ffffff;--glass:#0969da;--value:#bf8700}
@media (prefers-color-scheme:dark){svg{--bg:#0d1117;--panel:#161b22;--edge:#30363d;--text:#e6edf3;--muted:#9198a1;--accent:#4493f8;--accentText:#0d1117;
--ok:#3fb950;--okBg:#12261e;--warn:#d29922;--warnBg:#272115;--bad:#f85149;--badBg:#2d1215;--field:#0d1117;--glass:#4493f8;--value:#e3b341}}
text{font-family:${SANS};fill:var(--text)}
.mono{font-family:${MONO}}
.muted{fill:var(--muted)}
.bg{fill:var(--bg)}
.panel{fill:var(--panel);stroke:var(--edge)}
.field{fill:var(--field);stroke:var(--edge)}
.edge{stroke:var(--edge)}
.a{transform-box:fill-box;transform-origin:center}
`;
const REDUCED = `.pk,.caret{opacity:0}@media (prefers-reduced-motion:reduce){*{animation:none!important}}`;

// ------------------------------------------------------------------ hero
const HERO = {
  en: {
    title: 'veilform: the agent asks, you type, the value goes straight to its destination',
    colAgent: 'AI agent · sees metadata only',
    colYou: 'Your browser · 127.0.0.1',
    colDest: 'Destination',
    ask1: 'I need the payment',
    ask2: 'provider access token.',
    meta: 'metadata only',
    winTitle: 'Acme Store — payment credentials',
    f1: 'Access token',
    f2: 'Environment',
    env: 'production',
    btn: 'Save securely',
    saved: 'Saved. The agent only gets the names.',
    value: 'value',
    never: 'never seen',
    wall: 'values never cross',
  },
  es: {
    title: 'veilform: el agente pide, tú escribes, el valor va directo a su destino',
    colAgent: 'Agente de IA · solo ve metadatos',
    colYou: 'Tu navegador · 127.0.0.1',
    colDest: 'Destino',
    ask1: 'Necesito el access token',
    ask2: 'del proveedor de pagos.',
    meta: 'solo metadatos',
    winTitle: 'Acme Store — credenciales de pago',
    f1: 'Access token',
    f2: 'Entorno',
    env: 'production',
    btn: 'Guardar de forma segura',
    saved: 'Guardado. El agente solo recibe nombres.',
    value: 'valor',
    never: 'nunca lo ve',
    wall: 'los valores no cruzan',
  },
};

function hero(lang) {
  const s = HERO[lang];
  const T = 12; // seconds per loop
  const W = 960;
  const H = 440;
  const css = [];
  const anim = (cls, name, stops, ease = 'cubic-bezier(.2,.7,.2,1)') => {
    css.push(kf(name, T, stops));
    css.push(`.${cls}{animation:${name} ${T}s ${ease} infinite both}`);
  };
  // appear at t (fade + rise), stay until the loop fades out
  const appear = (cls, t, dy = 6) =>
    anim(cls, `k_${cls}`, [
      [0, `opacity:0;transform:translateY(${dy}px)`],
      [t, `opacity:0;transform:translateY(${dy}px)`],
      [t + 0.45, 'opacity:1;transform:translateY(0)'],
      [T, 'opacity:1;transform:translateY(0)'],
    ]);
  // a packet that travels from (0,0) to (dx,dy) between t0 and t1 (only visible while moving)
  const travel = (cls, t0, t1, dx, dy) =>
    anim(
      cls,
      `k_${cls}`,
      [
        [0, 'opacity:0;transform:translate(0,0)'],
        [t0, 'opacity:0;transform:translate(0,0)'],
        [t0 + 0.12, 'opacity:1;transform:translate(0,0)'],
        [t1 - 0.12, `opacity:1;transform:translate(${dx}px,${dy}px)`],
        [t1, `opacity:0;transform:translate(${dx}px,${dy}px)`],
        [T, `opacity:0;transform:translate(${dx}px,${dy}px)`],
      ],
      'ease-in-out',
    );

  // Whole scene fades in at the start and out at the end of each loop (no hard cut).
  anim('scene', 'k_scene', [[0, 'opacity:0'], [0.35, 'opacity:1'], [11.35, 'opacity:1'], [11.9, 'opacity:0'], [T, 'opacity:0']], 'ease-in-out');

  // columns
  const A = { x: 24, y: 64, w: 272, h: 352 }; // agent
  const WALL = { x: 308, w: 16 };
  const B = { x: 338, y: 64, w: 336, h: 352 }; // browser window
  const D = { x: 700, y: 64, w: 236 }; // destinations

  appear('ask', 0.3);
  appear('call', 1.0);
  travel('pmeta', 1.5, 2.4, B.x + 24 - (A.x + 236), 0);
  anim('win', 'k_win', [
    [0, 'opacity:0;transform:scale(.97)'],
    [2.25, 'opacity:0;transform:scale(.97)'],
    [2.8, 'opacity:1;transform:scale(1)'],
    [T, 'opacity:1;transform:scale(1)'],
  ]);
  appear('f1', 2.9, 8);
  appear('f2', 3.2, 8);
  appear('btn', 3.5, 8);

  // the secret is typed: dots appear one by one
  const DOTS = 14;
  const dots = [];
  for (let i = 0; i < DOTS; i++) {
    const t = 3.9 + i * 0.16;
    css.push(kf(`k_d${i}`, T, [[0, 'opacity:0;transform:scale(.3)'], [t, 'opacity:0;transform:scale(.3)'], [t + 0.12, 'opacity:1;transform:scale(1)'], [T, 'opacity:1;transform:scale(1)']]));
    css.push(`.d${i}{animation:k_d${i} ${T}s ease-out infinite both}`);
    dots.push(`<circle class="a d${i}" cx="${B.x + 36 + i * 13}" cy="${B.y + 132}" r="3.6" fill="var(--text)"/>`);
  }
  // caret follows the dots
  css.push(
    kf('k_caret', T, [
      [0, 'opacity:0;transform:translateX(0)'],
      [3.5, 'opacity:0;transform:translateX(0)'],
      [3.7, 'opacity:1;transform:translateX(0)'],
      ...Array.from({ length: DOTS }, (_, i) => [3.9 + i * 0.16 + 0.1, `opacity:1;transform:translateX(${(i + 1) * 13}px)`]),
      [6.35, `opacity:1;transform:translateX(${DOTS * 13}px)`],
      [6.5, `opacity:0;transform:translateX(${DOTS * 13}px)`],
      [T, `opacity:0;transform:translateX(${DOTS * 13}px)`],
    ]),
  );
  css.push(`.caret{animation:k_caret ${T}s linear infinite both}`);
  appear('envv', 6.1, 0);
  anim('press', 'k_press', [[0, 'transform:scale(1)'], [6.7, 'transform:scale(1)'], [6.85, 'transform:scale(.94)'], [7.05, 'transform:scale(1)'], [T, 'transform:scale(1)']], 'ease-in-out');
  appear('saved', 8.3, 4);

  // value packets: window -> four destinations
  const dest = [
    ['.env', '~/acme-store/.env'],
    ['SSH', 'prod-vps:/etc/acme.env'],
    ['SQL', 'appdb · public.settings'],
    ['API', 'Vault · 1Password · GitHub'],
  ];
  const btnY = B.y + 236;
  const destY = (i) => D.y + 38 + i * 78;
  const px0 = B.x + B.w - 8;
  dest.forEach((_, i) => {
    travel(`pv${i}`, 7.0 + i * 0.12, 7.9 + i * 0.12, D.x + 6 - px0, destY(i) + 28 - btnY);
    anim(`dc${i}`, `k_dc${i}`, [
      [0, 'stroke:var(--edge)'],
      [7.75 + i * 0.12, 'stroke:var(--edge)'],
      [8.0 + i * 0.12, 'stroke:var(--ok)'],
      [T, 'stroke:var(--ok)'],
    ]);
    appear(`dk${i}`, 7.9 + i * 0.12, 0);
  });

  // names go back to the agent (they may cross the wall); the value does not
  travel('pnames', 8.7, 9.6, A.x + 40 - (B.x + 24), 0);
  appear('res', 9.5);
  appear('val', 10.0);
  css.push(kf('k_strike', T, [[0, 'stroke-dashoffset:120'], [10.35, 'stroke-dashoffset:120'], [10.85, 'stroke-dashoffset:0'], [T, 'stroke-dashoffset:0']]));
  css.push(`.strike{stroke-dasharray:120;animation:k_strike ${T}s ease-out infinite both}`);
  // wall shimmer when the value would come close
  anim('wallglow', 'k_wallglow', [[0, 'opacity:.18'], [7.0, 'opacity:.18'], [7.5, 'opacity:.42'], [8.6, 'opacity:.18'], [T, 'opacity:.18']], 'ease-in-out');


  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t">
<title id="t">${esc(s.title)}</title>
<style>${THEME}${css.join('\n')}
${REDUCED}</style>
<defs>
  <pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="2" height="6" fill="var(--glass)"/></pattern>
  <linearGradient id="glass" x1="0" x2="1"><stop offset="0" stop-color="var(--glass)" stop-opacity=".05"/><stop offset=".5" stop-color="var(--glass)" stop-opacity=".22"/><stop offset="1" stop-color="var(--glass)" stop-opacity=".05"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" rx="16" class="bg"/>
<rect x=".5" y=".5" width="${W - 1}" height="${H - 1}" rx="16" fill="none" class="edge"/>
<g font-size="12.5" font-weight="600" class="muted">
  <text x="${A.x}" y="44" class="muted">${esc(s.colAgent)}</text>
  <text x="${B.x}" y="44" class="muted">${esc(s.colYou)}</text>
  <text x="${D.x}" y="44" class="muted">${esc(s.colDest)}</text>
</g>
<g class="scene">
  <!-- agent column -->
  <rect x="${A.x}" y="${A.y}" width="${A.w}" height="${A.h}" rx="12" class="panel"/>
  <g class="a ask"><rect x="${A.x + 14}" y="${A.y + 16}" width="${A.w - 28}" height="54" rx="12" fill="var(--bg)" class="edge" stroke="var(--edge)"/>
    <text x="${A.x + 28}" y="${A.y + 38}" font-size="14">${esc(s.ask1)}</text><text x="${A.x + 28}" y="${A.y + 58}" font-size="14">${esc(s.ask2)}</text></g>
  <g class="a call"><rect x="${A.x + 14}" y="${A.y + 84}" width="${A.w - 28}" height="74" rx="10" fill="var(--bg)" stroke="var(--accent)" stroke-opacity=".55"/>
    <text x="${A.x + 26}" y="${A.y + 106}" font-size="12.5" class="mono" fill="var(--accent)" style="fill:var(--accent)">secret_request({</text>
    <text x="${A.x + 40}" y="${A.y + 125}" font-size="12.5" class="mono">fields:["MP_ACCESS_TOKEN"]</text>
    <text x="${A.x + 26}" y="${A.y + 144}" font-size="12.5" class="mono" style="fill:var(--accent)">})</text>
    <text x="${A.x + A.w - 26}" y="${A.y + 144}" font-size="11" text-anchor="end" class="muted">${esc(s.meta)}</text></g>
  <g class="a res"><rect x="${A.x + 14}" y="${A.y + 196}" width="${A.w - 28}" height="40" rx="10" fill="var(--okBg)" stroke="var(--ok)" stroke-opacity=".6"/>
    <text x="${A.x + 26}" y="${A.y + 221}" font-size="12.5" class="mono">{stored:["MP_ACCESS_TOKEN"]}</text></g>
  <g class="a val"><rect x="${A.x + 14}" y="${A.y + 250}" width="${A.w - 28}" height="40" rx="10" fill="var(--badBg)" stroke="var(--bad)" stroke-opacity=".5"/>
    <text x="${A.x + 26}" y="${A.y + 275}" font-size="12.5" class="mono">${esc(s.value)}:</text>
    <g fill="var(--text)">${Array.from({ length: 8 }, (_, i) => `<circle cx="${A.x + 26 + s.value.length * 7.6 + 20 + i * 11}" cy="${A.y + 270}" r="3.4"/>`).join('')}</g>
    <line class="strike" x1="${A.x + 26 + s.value.length * 7.6 + 12}" y1="${A.y + 270}" x2="${A.x + 26 + s.value.length * 7.6 + 106}" y2="${A.y + 270}" stroke="var(--bad)" stroke-width="2.4" stroke-linecap="round"/>
    <text x="${A.x + A.w - 26}" y="${A.y + 275}" font-size="12" font-weight="600" text-anchor="end" style="fill:var(--bad)">${esc(s.never)}</text></g>

  <!-- the glass wall between the model and your values -->
  <rect x="${WALL.x}" y="${A.y}" width="${WALL.w}" height="${A.h}" rx="6" fill="url(#glass)"/>
  <rect class="wallglow" x="${WALL.x}" y="${A.y}" width="${WALL.w}" height="${A.h}" rx="6" fill="url(#hatch)" opacity=".18"/>
  <text transform="translate(${WALL.x + WALL.w / 2 + 4} ${A.y + A.h / 2}) rotate(-90)" font-size="11" font-weight="600" text-anchor="middle" style="fill:var(--accent)">${esc(s.wall)}</text>

  <!-- browser window (the real local page, simplified) -->
  <g class="a win">
    <rect x="${B.x}" y="${B.y}" width="${B.w}" height="${B.h}" rx="12" class="panel"/>
    <path d="M${B.x} ${B.y + 34}h${B.w}" class="edge"/>
    <circle cx="${B.x + 18}" cy="${B.y + 17}" r="5" fill="#ff5f57"/><circle cx="${B.x + 34}" cy="${B.y + 17}" r="5" fill="#febc2e"/><circle cx="${B.x + 50}" cy="${B.y + 17}" r="5" fill="#28c840"/>
    <rect x="${B.x + 70}" y="${B.y + 8}" width="${B.w - 86}" height="18" rx="6" fill="var(--bg)"/>
    <text x="${B.x + 78}" y="${B.y + 21}" font-size="11" class="muted">127.0.0.1:41723/p/…</text>
    <text x="${B.x + 20}" y="${B.y + 64}" font-size="15" font-weight="700">${esc(s.winTitle)}</text>
    <g class="a f1"><text x="${B.x + 20}" y="${B.y + 100}" font-size="12.5" font-weight="600">${esc(s.f1)}</text>
      <rect x="${B.x + 20}" y="${B.y + 112}" width="${B.w - 40}" height="40" rx="8" class="field"/></g>
    ${dots.join('\n    ')}
    <rect class="caret" x="${B.x + 31}" y="${B.y + 123}" width="1.6" height="18" fill="var(--accent)"/>
    <g class="a f2"><text x="${B.x + 20}" y="${B.y + 180}" font-size="12.5" font-weight="600">${esc(s.f2)}</text>
      <rect x="${B.x + 20}" y="${B.y + 190}" width="${B.w - 40}" height="34" rx="8" class="field"/>
      <path d="M${B.x + B.w - 40} ${B.y + 204}l5 5 5-5" fill="none" stroke="var(--muted)" stroke-width="1.6"/></g>
    <text class="a envv" x="${B.x + 32}" y="${B.y + 212}" font-size="13">${esc(s.env)}</text>
    <g class="a btn"><g class="a press"><rect x="${B.x + 20}" y="${B.y + 246}" width="${Math.max(150, s.btn.length * 8 + 36)}" height="36" rx="8" fill="var(--accent)"/>
      <text x="${B.x + 20 + Math.max(150, s.btn.length * 8 + 36) / 2}" y="${B.y + 269}" font-size="13" font-weight="700" text-anchor="middle" style="fill:var(--accentText)">${esc(s.btn)}</text></g></g>
    <g class="a saved"><rect x="${B.x + 20}" y="${B.y + 296}" width="${B.w - 40}" height="36" rx="8" fill="var(--okBg)"/>
      <path d="M${B.x + 34} ${B.y + 314}l5 5 9-10" fill="none" stroke="var(--ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
      <text x="${B.x + 54}" y="${B.y + 319}" font-size="12" style="fill:var(--ok)" font-weight="600">${esc(s.saved)}</text></g>
  </g>

  <!-- destinations -->
  ${dest
    .map(
      ([k, v], i) => `<g><rect class="dc${i}" x="${D.x}" y="${destY(i)}" width="${D.w}" height="56" rx="10" fill="var(--panel)" stroke="var(--edge)" stroke-width="1.5"/>
    <text x="${D.x + 16}" y="${destY(i) + 24}" font-size="13.5" font-weight="700" class="mono">${esc(k)}</text>
    <text x="${D.x + 16}" y="${destY(i) + 43}" font-size="11.5" class="muted mono">${esc(v)}</text>
    <g class="a dk${i}"><circle cx="${D.x + D.w - 22}" cy="${destY(i) + 28}" r="10" fill="var(--okBg)"/><path d="M${D.x + D.w - 27} ${destY(i) + 28}l3.5 3.5 6.5-7" fill="none" stroke="var(--ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></g></g>`,
    )
    .join('\n  ')}

  <!-- packets -->
  <g class="pk pmeta"><rect x="${A.x + 196}" y="${A.y + 112}" width="44" height="18" rx="9" fill="var(--accent)"/><text x="${A.x + 218}" y="${A.y + 125}" font-size="10" font-weight="700" text-anchor="middle" style="fill:var(--accentText)">schema</text></g>
  ${dest.map((_, i) => `<g class="pk pv${i}"><circle cx="${px0}" cy="${btnY}" r="7" fill="var(--value)"/><circle cx="${px0}" cy="${btnY}" r="12" fill="var(--value)" opacity=".25"/></g>`).join('\n  ')}
  <g class="pk pnames"><rect x="${B.x + 4}" y="${A.y + 206}" width="54" height="18" rx="9" fill="var(--ok)"/><text x="${B.x + 31}" y="${A.y + 219}" font-size="10" font-weight="700" text-anchor="middle" style="fill:var(--bg)">names</text></g>
</g>
</svg>
`;
  return svg;
}

// ------------------------------------------------------------- diagram
const DIA = {
  en: {
    title: 'Who sees what: the model, you, and the veilform MCP server',
    lanes: ['What the model sees', 'What you see', 'What the MCP server does'],
    cols: ['1 · ask', '2 · type', '3 · store', '4 · use'],
    model: [['secret_request', 'schema: names, labels, rules'], ['nothing', 'waits on secret_wait'], ['{stored:["MP_…"]}', 'names + status only'], ['${secret:MP_…}', 'exit 0 · [REDACTED]']],
    you: [['local page opens', '127.0.0.1 · one-time link'], ['you type the value', 'secret field, no autofill'], ['"Saved" + destination', 'what goes where'], ['approve the literal', 'command / request']],
    server: [['renders the form', 'from the schema'], ['receives the value', 'CSRF · Origin · cookie'], ['writes it', '.env · SQL · SSH · API'], ['resolves at use time', 'then scrubs the output']],
    glass: 'values never cross this line',
    names: 'names',
    meta: 'schema',
  },
  es: {
    title: 'Quién ve qué: el modelo, tú y el servidor MCP veilform',
    lanes: ['Lo que ve el modelo', 'Lo que ves tú', 'Lo que hace el servidor MCP'],
    cols: ['1 · pide', '2 · escribes', '3 · guarda', '4 · usa'],
    model: [['secret_request', 'esquema: nombres, reglas'], ['nada', 'espera con secret_wait'], ['{stored:["MP_…"]}', 'solo nombres y estado'], ['${secret:MP_…}', 'exit 0 · [REDACTED]']],
    you: [['se abre la página local', '127.0.0.1 · enlace de un uso'], ['escribes el valor', 'campo secreto (••••)'], ['"Guardado" + destino', 'qué va a dónde'], ['apruebas lo literal', 'comando / petición']],
    server: [['arma el formulario', 'a partir del esquema'], ['recibe el valor', 'CSRF · Origin · cookie'], ['lo escribe', '.env · SQL · SSH · API'], ['lo resuelve al usarlo', 'y limpia la salida']],
    glass: 'los valores nunca cruzan esta línea',
    names: 'nombres',
    meta: 'esquema',
  },
};

function diagram(lang) {
  const s = DIA[lang];
  const W = 960;
  const H = 470;
  const LX = 24; // lane label column
  const C0 = 214; // first column x
  const CW = 182; // column width
  const BW = 166;
  const BH = 58;
  const laneY = [70, 230, 340]; // box top per lane
  const glassY = 160;
  const cx = (c) => C0 + c * CW + BW / 2;
  const css = [];
  // particle: moves along a polyline, loop `dur`, `delay`
  let pid = 0;
  const particles = [];
  const particle = (pts, { dur = 3.2, delay = 0, kind = 'value', label, blocked = false } = {}) => {
    const id = `q${pid++}`;
    const segs = [];
    let len = 0;
    for (let i = 1; i < pts.length; i++) {
      const l = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
      segs.push(l);
      len += l;
    }
    const moveEnd = 0.8; // fraction of the loop spent moving
    const stops = [`0%{opacity:0;transform:translate(${pts[0][0]}px,${pts[0][1]}px)}`, `6%{opacity:1}`];
    let acc = 0;
    for (let i = 1; i < pts.length; i++) {
      acc += segs[i - 1];
      const f = ((acc / len) * moveEnd * 100).toFixed(2);
      stops.push(`${f}%{transform:translate(${pts[i][0]}px,${pts[i][1]}px)${i === pts.length - 1 ? ';opacity:' + (blocked ? '0' : '1') : ''}}`);
    }
    stops.push(`${(moveEnd * 100 + 8).toFixed(2)}%{opacity:0;transform:translate(${pts.at(-1)[0]}px,${pts.at(-1)[1]}px)}`);
    stops.push(`100%{opacity:0;transform:translate(${pts.at(-1)[0]}px,${pts.at(-1)[1]}px)}`);
    css.push(`@keyframes k_${id}{${stops.join('')}}`);
    css.push(`.${id}{opacity:0;animation:k_${id} ${dur}s linear ${delay}s infinite}`);
    const body =
      kind === 'value'
        ? `<circle r="6.5" fill="var(--value)"/><circle r="11" fill="var(--value)" opacity=".22"/>`
        : `<rect x="${-(label.length * 3.3 + 10)}" y="-9" width="${label.length * 6.6 + 20}" height="18" rx="9" fill="${kind === 'names' ? 'var(--ok)' : 'var(--accent)'}"/><text y="3.5" font-size="10" font-weight="700" text-anchor="middle" style="fill:var(--bg)">${esc(label)}</text>`;
    particles.push(`<g class="pt ${id}">${body}</g>`);
    if (blocked) {
      // ripple where the value hits the glass
      const [bx, by] = pts.at(-1);
      const rid = `r${id}`;
      const f = moveEnd * 100;
      css.push(`@keyframes k_${rid}{0%,${(f - 1).toFixed(1)}%{opacity:0;transform:scale(.4)}${(f + 2).toFixed(1)}%{opacity:.9;transform:scale(1)}${(f + 14).toFixed(1)}%{opacity:0;transform:scale(1.6)}100%{opacity:0}}`);
      css.push(`.${rid}{opacity:0;transform-box:fill-box;transform-origin:center;animation:k_${rid} ${dur}s ease-out ${delay}s infinite}`);
      particles.push(`<g class="pt ${rid}"><circle cx="${bx}" cy="${by}" r="14" fill="none" stroke="var(--bad)" stroke-width="2"/><path d="M${bx - 5} ${by - 5}l10 10M${bx + 5} ${by - 5}l-10 10" stroke="var(--bad)" stroke-width="2" stroke-linecap="round"/></g>`);
    }
  };

  const top = (l) => laneY[l];
  const bot = (l) => laneY[l] + BH;
  // 1. schema goes down from the model to the server (metadata may cross)
  particle([[cx(0) - 30, bot(0)], [cx(0) - 30, top(2)]], { kind: 'meta', label: s.meta, dur: 4, delay: 0 });
  // server opens the page for you
  particle([[cx(0) + 30, top(2)], [cx(0) + 30, bot(1)]], { kind: 'meta', label: '127.0.0.1', dur: 4, delay: 1.2 });
  // 2. value: you -> server -> store (column 3)
  particle([[cx(1), bot(1)], [cx(1), top(2)], [cx(1) + BW / 2, top(2) + BH / 2], [cx(2) - BW / 2, top(2) + BH / 2]], { dur: 3.6, delay: 0.4 });
  particle([[cx(1), bot(1)], [cx(1), top(2)], [cx(1) + BW / 2, top(2) + BH / 2], [cx(2) - BW / 2, top(2) + BH / 2]], { dur: 3.6, delay: 2.2 });
  // a value that tries to go up towards the model is stopped at the glass
  particle([[cx(1) + 40, top(1)], [cx(1) + 40, glassY + 22]], { dur: 3.6, delay: 1.3, blocked: true });
  // 3. only names go up to the model
  particle([[cx(2), top(2)], [cx(2), bot(0)]], { kind: 'names', label: s.names, dur: 4, delay: 0.8 });
  // 4. ${secret:x} goes down, approval, value resolved inside the server, redacted output goes up
  particle([[cx(3) - 36, bot(0)], [cx(3) - 36, top(1)]], { kind: 'meta', label: '${secret:…}', dur: 4.2, delay: 0.2 });
  particle([[cx(3) - 36, bot(1)], [cx(3) - 36, top(2)]], { kind: 'meta', label: 'OK', dur: 4.2, delay: 1.6 });
  particle([[cx(2) + BW / 2, top(2) + BH / 2 + 12], [cx(3) - BW / 2, top(2) + BH / 2 + 12]], { dur: 3, delay: 1.1 });
  particle([[cx(3) + 40, top(2)], [cx(3) + 40, bot(0)]], { kind: 'names', label: 'exit 0', dur: 4.2, delay: 2.6 });

  const box = (l, c, [a, b]) => {
    const x = C0 + c * CW;
    const y = laneY[l];
    const strong = l === 0 ? 'var(--accent)' : l === 1 ? 'var(--edge)' : 'var(--ok)';
    return `<g><rect x="${x}" y="${y}" width="${BW}" height="${BH}" rx="10" fill="var(--bg)" stroke="${strong}" stroke-opacity="${l === 1 ? 1 : 0.55}" stroke-width="1.4"/>
  <text x="${x + 12}" y="${y + 24}" font-size="${l === 0 ? 11.5 : 13}" font-weight="650" ${l === 0 ? 'class="mono"' : ''}>${esc(a)}</text>
  <text x="${x + 12}" y="${y + 43}" font-size="11.5" class="muted">${esc(b)}</text></g>`;
  };
  const lane = (l, y0, h, label) => `<rect x="12" y="${y0}" width="${W - 24}" height="${h}" rx="12" class="panel"/>
<text x="${LX}" y="${y0 + h / 2 + 4}" font-size="13" font-weight="700">${esc(label)}</text>`;

  // static guide lines (visible also with reduced motion)
  const guides = [
    [cx(0) - 30, bot(0), cx(0) - 30, top(2)],
    [cx(0) + 30, top(2), cx(0) + 30, bot(1)],
    [cx(1), bot(1), cx(1), top(2)],
    [cx(2), top(2), cx(2), bot(0)],
    [cx(3) - 36, bot(0), cx(3) - 36, top(2)],
    [cx(3) + 40, top(2), cx(3) + 40, bot(0)],
    [cx(1) + BW / 2, top(2) + BH / 2, cx(2) - BW / 2, top(2) + BH / 2],
    [cx(2) + BW / 2, top(2) + BH / 2 + 12, cx(3) - BW / 2, top(2) + BH / 2 + 12],
  ]
    .map(([x1, y1, x2, y2]) => `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="var(--muted)" stroke-opacity=".35" stroke-width="1.4" stroke-dasharray="3 5"/>`)
    .join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t">
<title id="t">${esc(s.title)}</title>
<style>${THEME}
${css.join('\n')}
@keyframes k_glass{0%,100%{opacity:.16}50%{opacity:.3}}
.glassHatch{animation:k_glass 3.6s ease-in-out infinite}
${REDUCED}
@media (prefers-reduced-motion:reduce){.pt{display:none}}</style>
<defs>
  <pattern id="hatch" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="2" height="7" fill="var(--glass)"/></pattern>
  <linearGradient id="glass" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--glass)" stop-opacity=".06"/><stop offset=".5" stop-color="var(--glass)" stop-opacity=".2"/><stop offset="1" stop-color="var(--glass)" stop-opacity=".06"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" rx="16" class="bg"/>
<rect x=".5" y=".5" width="${W - 1}" height="${H - 1}" rx="16" fill="none" class="edge"/>
${s.cols.map((c, i) => `<text x="${C0 + i * CW + 4}" y="40" font-size="12" font-weight="700" class="muted" letter-spacing=".04em">${esc(c.toUpperCase())}</text>`).join('\n')}
${lane(0, 56, 88, s.lanes[0])}
${lane(1, 216, 86, s.lanes[1])}
${lane(2, 326, 86, s.lanes[2])}
<rect x="12" y="${glassY}" width="${W - 24}" height="40" rx="8" fill="url(#glass)"/>
<rect class="glassHatch" x="12" y="${glassY}" width="${W - 24}" height="40" rx="8" fill="url(#hatch)" opacity=".2"/>
<text x="${LX}" y="${glassY + 25}" font-size="12" font-weight="700" style="fill:var(--accent)">${esc(s.glass)}</text>
${guides}
<g>${particles.join('\n')}</g>
${s.model.map((b, c) => box(0, c, b)).join('\n')}
${s.you.map((b, c) => box(1, c, b)).join('\n')}
${s.server.map((b, c) => box(2, c, b)).join('\n')}
${legend(lang, W, H)}
</svg>
`;
}

function legend(lang, W, H) {
  const items = lang === 'es'
    ? [['value', 'valor'], ['names', 'nombres / estado'], ['meta', 'metadatos']]
    : [['value', 'value'], ['names', 'names / status'], ['meta', 'metadata']];
  const widths = items.map(([, t]) => 34 + t.length * 6.4 + 18);
  let x = W - 24 - widths.reduce((a, b) => a + b, 0);
  const parts = items.map(([k, t], i) => {
    const sw = k === 'value' ? `<circle cx="${x + 8}" cy="0" r="6" fill="var(--value)"/>` : `<rect x="${x}" y="-8" width="24" height="16" rx="8" fill="${k === 'names' ? 'var(--ok)' : 'var(--accent)'}"/>`;
    const out = `${sw}<text x="${x + 32}" y="4" class="muted">${esc(t)}</text>`;
    x += widths[i];
    return out;
  });
  return `<g transform="translate(0 ${H - 32})" font-size="11.5">${parts.join('')}</g>`;
}

// --------------------------------------------------------------- icons
const ICONS = {
  form: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M7 9h10"/><circle cx="8" cy="14.5" r=".9" class="f"/><circle cx="11" cy="14.5" r=".9" class="f"/><circle cx="14" cy="14.5" r=".9" class="f"/><circle cx="17" cy="14.5" r=".9" class="f"/>',
  capture: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 8h18"/><path d="M9 13h2M13 13h2M12 11v1M12 14v1"/><circle cx="12" cy="13" r="3.5"/>',
  key: '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M15 12v2"/>',
  write: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9 14h6M12 11l3 3-3 3"/>',
  stores: '<ellipse cx="12" cy="6" rx="7" ry="2.6"/><path d="M5 6v6c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V6"/><path d="M5 12v6c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6v-6"/>',
  approve: '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/>',
};
function icon(body) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20"><style>svg{--c:#0969da}@media (prefers-color-scheme:dark){svg{--c:#4493f8}}*{fill:none;stroke:var(--c);stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}.f{fill:var(--c);stroke:none}</style>${body}</svg>\n`;
}

const sizes = [];
const write = (rel, content) => {
  writeFileSync(path.join(OUT, rel), content);
  sizes.push(`${(Buffer.byteLength(content) / 1024).toFixed(1).padStart(6)} KB  docs/assets/${rel}`);
};
for (const lang of ['en', 'es']) {
  write(`hero-${lang}.svg`, hero(lang));
  write(`how-it-works-${lang}.svg`, diagram(lang));
}
for (const [k, v] of Object.entries(ICONS)) write(`icons/${k}.svg`, icon(v));
process.stdout.write(sizes.join('\n') + '\n');
