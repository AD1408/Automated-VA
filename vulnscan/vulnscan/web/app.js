// VulnScan web UI - no build step, no framework.
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const view = $("#view");
const SEVS = ["critical", "high", "medium", "low", "info"];
const STAGE_LABEL = { ingest: "Ingest", recon: "Recon", plan: "Plan", scan: "Scan", merge: "Merge", triage: "Triage", report: "Report" };
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
let pollTimer = null, clockTimer = null;

// ------------------------------------------------------------------ utils
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const apiKey = () => { try { return localStorage.getItem("vulnscan_api_key") || ""; } catch { return ""; } };
async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (apiKey()) headers["X-API-Key"] = apiKey();
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  let signal = opts.signal;
  let timer = null;
  if (opts.timeoutMs && !signal && "AbortController" in window) {
    const ac = new AbortController(); signal = ac.signal;
    timer = setTimeout(() => ac.abort(), opts.timeoutMs);
  }
  let r;
  try {
    r = await fetch(path, { ...opts, headers, signal });
  } catch (err) {
    if (err.name === "AbortError") throw new Error("The request timed out. If you're using a local model, it may still be loading — try again in a moment.");
    throw new Error("Could not reach the API. Is the server running?");
  } finally { if (timer) clearTimeout(timer); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) { const e = new Error(typeof data === "object" ? JSON.stringify(data.detail ?? data) : data); e.status = r.status; e.data = data; throw e; }
  return data;
}
function toast(msg, err = false) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast on" + (err ? " err" : "");
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.className = "toast"), 4200);
}
function countUp(el, to, ms = 900) {
  const from = Number(el.dataset.v || 0); el.dataset.v = to;
  if (REDUCED || from === to) { el.textContent = to; return; }
  const t0 = performance.now();
  const step = (now) => { const p = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * e); if (p < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
// tiny safe markdown: escape first, then format
function md(src) {
  let s = esc(src || "");
  const blocks = [];
  s = s.replace(/```[\w-]*\n?([\s\S]*?)```/g, (_, code) => { blocks.push(`<pre>${code}</pre>`); return `\u0000${blocks.length - 1}\u0000`; });
  s = s.replace(/^### (.*)$/gm, "<h4>$1</h4>").replace(/^## (.*)$/gm, "<h4>$1</h4>").replace(/^# (.*)$/gm, "<h4>$1</h4>")
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/^\s*[-*] (.*)$/gm, "<li>$1</li>").replace(/(<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`)
    .replace(/\n{2,}/g, "<br><br>");
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => blocks[i]);
}
const sevPill = (s) => `<span class="sev sev-${s}">${s}</span>`;
const VERDICT = {
  verified: { label: "verified", cls: "v-verified", icon: "✓" },
  likely: { label: "likely", cls: "v-likely", icon: "◆" },
  uncertain: { label: "needs review", cls: "v-uncertain", icon: "?" },
  false_positive: { label: "false positive", cls: "v-fp", icon: "✕" },
};
const verdictPill = (f) => { const v = VERDICT[f.verdict] || VERDICT.uncertain; return `<span class="vpill ${v.cls}" title="confidence ${f.confidence_score}%">${v.icon} ${v.label} · ${f.confidence_score}%</span>`; };
const confMeter = (score) => `<div class="confmeter"><i style="width:${score}%; --c:${score >= 80 ? "var(--ok)" : score >= 58 ? "var(--sev-medium)" : score >= 20 ? "var(--sev-high)" : "var(--fail)"}"></i></div>`;
const locText = (l = {}) => (l.file ? l.file + (l.line ? ":" + l.line : "") : l.url ? l.url + (l.param ? ` [${l.param}]` : "")
  : l.host ? l.host + (l.port ? ":" + l.port : "") : l.component ? `${l.component}@${l.version || "?"}` : l.resource || "-");
function hash32(str) { let h = 2166136261; for (const c of str) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; }
function animateRings(root = document) {
  if (REDUCED) return;
  for (const el of root.querySelectorAll(".ring, .fw-ring")) {
    const target = el.style.getPropertyValue("--p");
    if (!target) continue;
    el.style.setProperty("--p", "0");
    void el.offsetWidth; // reflow so the transition runs
    requestAnimationFrame(() => el.style.setProperty("--p", target));
  }
}

// ------------------------------------------------------------------ animated background (particle network)
(function background() {
  const c = $("#bg"), ctx = c.getContext("2d");
  let w, h, pts = [], running = !REDUCED;
  const N = innerWidth < 700 ? 28 : 64;
  const resize = () => { w = c.width = innerWidth * devicePixelRatio; h = c.height = innerHeight * devicePixelRatio; };
  resize(); addEventListener("resize", resize);
  for (let i = 0; i < N; i++) pts.push({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25 });
  const light = matchMedia("(prefers-color-scheme: light)").matches;
  function frame() {
    if (!running) return;
    ctx.clearRect(0, 0, w, h);
    const D = 150 * devicePixelRatio;
    for (const p of pts) { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > w) p.vx *= -1; if (p.y < 0 || p.y > h) p.vy *= -1; }
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
      const a = pts[i], b = pts[j], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (d < D) { ctx.strokeStyle = light ? `rgba(91,63,214,${.14 * (1 - d / D)})` : `rgba(124,140,255,${.22 * (1 - d / D)})`; ctx.lineWidth = devicePixelRatio; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
    }
    ctx.fillStyle = light ? "rgba(91,63,214,.35)" : "rgba(160,170,255,.55)";
    for (const p of pts) { ctx.beginPath(); ctx.arc(p.x, p.y, 1.6 * devicePixelRatio, 0, 7); ctx.fill(); }
    requestAnimationFrame(frame);
  }
  document.addEventListener("visibilitychange", () => { running = !document.hidden && !REDUCED; if (running) frame(); });
  frame();
})();

// ------------------------------------------------------------------ cyber boot screen
(function boot() {
  const el = document.getElementById("boot");
  if (!el) return;
  const log = document.getElementById("bootLog");
  const lines = [
    ["> initializing scanner core", "ok"],
    ["> loading OWASP Top 10 (2025) rulesets", "ok"],
    ["> loading OWASP LLM Top 10 rulesets", "ok"],
    ["> arming engines: semgrep · nuclei · zap · nmap", "ok"],
    ["> connecting knowledge base (RAG)", "ok"],
    ["> secure channel established", "ok"],
  ];
  const done = () => { el.classList.add("gone"); setTimeout(() => el.remove(), 700); };
  if (REDUCED) { setTimeout(done, 300); return; }
  let i = 0;
  const step = () => {
    if (i < lines.length && log) {
      const [t, s] = lines[i++];
      log.innerHTML += `${t} <b>[</b><span class="ok">OK</span><b>]</b>\n`;
      setTimeout(step, 230);
    } else {
      setTimeout(done, 450);
    }
  };
  setTimeout(step, 350);
})();

// ------------------------------------------------------------------ particle burst FX engine
const FX = (() => {
  const c = document.getElementById("fx");
  if (!c || REDUCED) return { burst() {}, ring() {} };
  const ctx = c.getContext("2d");
  let parts = [], raf = null;
  const resize = () => { c.width = innerWidth * devicePixelRatio; c.height = innerHeight * devicePixelRatio; };
  resize(); addEventListener("resize", resize);
  const COLORS = ["#7c5cff", "#22d3ee", "#a78bfa", "#5b8cff", "#67e8f9"];
  function tick() {
    ctx.clearRect(0, 0, c.width, c.height);
    const dpr = devicePixelRatio;
    parts = parts.filter((p) => p.life > 0);
    for (const p of parts) {
      p.life -= 0.016; p.x += p.vx; p.y += p.vy; p.vy += p.g; p.vx *= 0.98;
      const a = Math.max(0, p.life / p.max);
      ctx.globalAlpha = a;
      ctx.fillStyle = p.c; ctx.shadowBlur = 12 * dpr; ctx.shadowColor = p.c;
      ctx.beginPath(); ctx.arc(p.x * dpr, p.y * dpr, p.r * dpr * a, 0, 7); ctx.fill();
    }
    ctx.globalAlpha = 1; ctx.shadowBlur = 0;
    raf = parts.length ? requestAnimationFrame(tick) : (raf = null);
  }
  function start() { if (!raf) raf = requestAnimationFrame(tick); }
  return {
    burst(x, y, n = 16, spread = 4) {
      for (let i = 0; i < n; i++) {
        const ang = (Math.PI * 2 * i) / n + Math.random(), sp = spread * (0.4 + Math.random());
        parts.push({ x, y, vx: Math.cos(ang) * sp, vy: Math.sin(ang) * sp - 0.8, g: 0.1,
          r: 1.2 + Math.random() * 2, life: 0.55 + Math.random() * 0.45, max: 1.0, c: COLORS[(Math.random() * COLORS.length) | 0] });
      }
      start();
    },
  };
})();

function fxFlash() {
  if (REDUCED) return;
  const btn = document.getElementById("launch");
  const f = document.createElement("div");
  f.className = "fx-flash";
  if (btn) { const r = btn.getBoundingClientRect(); f.style.setProperty("--x", r.left + r.width / 2 + "px"); f.style.setProperty("--y", r.top + r.height / 2 + "px"); FX.burst(r.left + r.width / 2, r.top + r.height / 2, 40, 8); }
  document.body.appendChild(f);
  setTimeout(() => f.remove(), 700);
}

function burstFromEvent(e) {
  const x = e.clientX ?? (e.target.getBoundingClientRect().left + 20);
  const y = e.clientY ?? (e.target.getBoundingClientRect().top + 20);
  FX.burst(x, y);
}

// burst on every primary action click
document.addEventListener("click", (e) => {
  const t = e.target.closest(".btn.primary, .profile, .chip, .tab, .tabs button");
  if (t) burstFromEvent(e);
}, true);

// ------------------------------------------------------------------ header status
async function refreshHealth() {
  const chip = $("#llmChip");
  try {
    const h = await api("/api/health");
    const l = h.llm;
    chip.className = "status-chip " + (l.ready ? "ready" : l.enabled ? "warn" : "");
    chip.querySelector(".txt").textContent = l.enabled ? `${l.provider} · ${l.model}${l.ready ? "" : " (not ready)"}` : "No LLM (rules only)";
    chip.title = l.hint || l.error || "LLM used for triage, design review and explanations";
  } catch { chip.querySelector(".txt").textContent = "API offline"; }
}

// ------------------------------------------------------------------ router
function route() {
  clearInterval(pollTimer); clearInterval(clockTimer); closeDrawer();
  const h = location.hash || "#/";
  $$("nav a").forEach((a) => a.classList.toggle("active", h === a.getAttribute("href") || (h.startsWith("#/scan") && a.dataset.nav === "history") || (h.startsWith("#/audit") && a.dataset.nav === "audit")));
  view.classList.remove("view-enter"); void view.offsetWidth; view.classList.add("view-enter");
  if (h.startsWith("#/scan/")) return renderScan(decodeURIComponent(h.slice(7)));
  if (h.startsWith("#/audit/")) return renderAudit(decodeURIComponent(h.slice(8)));
  if (h === "#/audit") return renderAuditHome();
  if (h === "#/history") return renderHistory();
  if (h === "#/tools") return renderTools();
  return renderNew();
}
addEventListener("hashchange", route);

// ------------------------------------------------------------------ NEW SCAN
const TABS = [
  { id: "repo", icon: "⎇", label: "GitHub repo" },
  { id: "zip", icon: "🗜", label: "ZIP upload" },
  { id: "url", icon: "🌐", label: "Website" },
  { id: "llm", icon: "🤖", label: "AI chatbot" },
];
const PROFILES = [
  { id: "quick", name: "Quick", desc: "Fast essentials · ~2–5 min" },
  { id: "standard", name: "Standard", desc: "Active web + AI checks · ~10–25 min" },
  { id: "full", name: "Full", desc: "Everything incl. OpenVAS & garak · 1h+" },
];
const state = { tab: "repo", profile: "standard", file: null };

function renderNew() {
  view.innerHTML = `
  <section class="hero">
    <div class="orb-wrap"><div class="orb" id="orb"></div></div>
    <h1 class="glitch" data-text="Scan anything.">Scan anything.<br><span class="grad">Fix what matters.</span></h1>
    <p>Point VulnScan at <span class="typer" id="typer"></span> and get one prioritised report covering the OWASP Top 10 and the OWASP Top 10 for LLM apps.</p>
  </section>
  <section class="card composer">
    <div class="tabs" role="tablist">
      <div class="slider"></div>
      ${TABS.map((t) => `<button role="tab" data-tab="${t.id}"><span>${t.icon}</span>${t.label}</button>`).join("")}
    </div>
    <div id="tabBody"></div>
    <div class="field"><label>Scan depth</label></div>
    <div class="profiles">${PROFILES.map((p) => `<button class="profile" data-profile="${p.id}"><b>${p.name}</b><span>${p.desc}</span></button>`).join("")}</div>
    <details class="adv">
      <summary>Advanced options</summary>
      <div class="row2">
        <div class="field"><label>Auth header for the website (optional)</label><input class="input plain" id="authHeader" placeholder="Cookie: session=…   or   Authorization: Bearer …"></div>
        <div class="field"><label>Cloud account (Prowler, uses .env credentials)</label>
          <select class="input plain" id="cloud"><option value="">None</option><option>aws</option><option>azure</option><option>gcp</option><option>kubernetes</option></select></div>
      </div>
      <div class="field"><label>Skip tools (comma-separated)</label><input class="input plain" id="skipTools" placeholder="e.g. nikto, sqlmap"></div>
      <div class="field" id="advLlm"><label>Also red-team a chatbot endpoint (optional)</label><input class="input plain" id="advLlmUrl" placeholder="http://demo-chat:8090/chat"></div>
    </details>
    <div class="launch">
      <div class="scope-note">🔒 Websites and endpoints must be in <b>ALLOWED_TARGETS</b> or ownership-verified. Only scan systems you own or are authorised to test.</div>
      <button class="btn primary" id="launch">Launch scan <span aria-hidden="true">→</span></button>
    </div>
  </section>
  <section class="features">
    ${[["🧬", "Code & dependencies", "Semgrep, Bandit, Gitleaks, Syft + Grype, Trivy, ModelScan"],
       ["🌐", "Web & network", "ZAP, Nuclei, Nikto, SQLMap, Nmap, testssl, OpenVAS"],
       ["🤖", "AI / LLM security", "Prompt Guard 2, canary probes, garak, LLM design review"],
       ["📄", "One report", "HTML · PDF · JSON · SARIF, OWASP mapped, AI-triaged"]]
      .map(([i, b, s], k) => `<div class="feature" style="animation-delay:${0.15 + k * 0.08}s"><div class="fi">${i}</div><b>${b}</b><span>${s}</span></div>`).join("")}
  </section>`;
  $$(".tabs button").forEach((b) => b.onclick = () => setTab(b.dataset.tab));
  $$(".profile").forEach((b) => b.onclick = () => setProfile(b.dataset.profile));
  $("#launch").onclick = launch;
  setTab(state.tab); setProfile(state.profile); typer();
}

function typer() {
  const words = ["a GitHub repo", "a ZIP of your code", "your website", "your AI chatbot"];
  let wi = 0, ci = 0, del = false;
  const el = $("#typer"); if (!el) return;
  if (REDUCED) { el.textContent = words[0]; return; }
  (function tick() {
    if (!document.body.contains(el)) return;
    const w = words[wi];
    el.textContent = w.slice(0, ci);
    if (!del && ci++ === w.length) { del = true; return setTimeout(tick, 1500); }
    if (del && ci-- === 0) { del = false; wi = (wi + 1) % words.length; }
    setTimeout(tick, del ? 35 : 75);
  })();
}

function setTab(id) {
  state.tab = id;
  const btns = $$(".tabs button"), i = TABS.findIndex((t) => t.id === id), b = btns[i], slider = $(".tabs .slider");
  btns.forEach((x) => x.classList.toggle("on", x === b));
  slider.style.width = b.offsetWidth + "px"; slider.style.transform = `translateX(${b.offsetLeft - 5}px)`;
  $("#advLlm").style.display = id === "llm" ? "none" : "";
  const body = $("#tabBody");
  if (id === "repo") body.innerHTML = `<div class="field"><span class="ico">⎇</span><input class="input" id="target" placeholder="https://github.com/owner/repository" autocomplete="off"><div class="hint">Public repos work out of the box. Private repos need GITHUB_TOKEN in .env.</div></div>`;
  if (id === "url") body.innerHTML = `<div class="field"><span class="ico">🌐</span><input class="input" id="target" placeholder="http://juice-shop:3000" autocomplete="off"><div class="hint">Apps running on your PC: use <code>http://host.docker.internal:PORT</code>. Try the built-in targets <code>http://juice-shop:3000</code> or <code>http://dvwa</code>.</div></div>`;
  if (id === "llm") body.innerHTML = `
    <div class="field"><span class="ico">🤖</span><input class="input" id="target" placeholder="http://demo-chat:8090/chat" value="http://demo-chat:8090/chat" autocomplete="off"><div class="hint">Endpoint that accepts JSON and returns the bot's reply. The bundled demo chatbot runs at <code>http://demo-chat:8090/chat</code>.</div></div>
    <div class="row2"><div class="field"><label>Request body template ({{prompt}} is replaced)</label><textarea class="input plain" id="bodyTpl">{"message": "{{prompt}}"}</textarea></div>
    <div class="field"><label>Reply field in JSON response</label><input class="input plain" id="respPath" value="reply"><div class="hint">Dotted path, e.g. <code>choices.0.message.content</code></div></div></div>`;
  if (id === "zip") {
    body.innerHTML = `<div class="dropzone" id="drop" tabindex="0"><span class="big">📦</span><b id="dropTxt">${state.file ? esc(state.file.name) : "Drop a .zip here or click to choose"}</b><div class="hint">Source code archive · up to 500 MB</div><input type="file" id="file" accept=".zip" hidden></div>`;
    const dz = $("#drop"), fi = $("#file");
    dz.onclick = () => fi.click(); dz.onkeydown = (e) => { if (e.key === "Enter") fi.click(); };
    fi.onchange = () => pickFile(fi.files[0]);
    dz.ondragover = (e) => { e.preventDefault(); dz.classList.add("over"); };
    dz.ondragleave = () => dz.classList.remove("over");
    dz.ondrop = (e) => { e.preventDefault(); dz.classList.remove("over"); pickFile(e.dataTransfer.files[0]); };
  }
  const t = $("#target");
  if (t) { t.focus(); t.onkeydown = (e) => { if (e.key === "Enter") launch(); };
    t.oninput = () => { if (state.tab === "url" && /github\.com\/[^/]+\/[^/]+/.test(t.value)) { const v = t.value; setTab("repo"); $("#target").value = v; toast("Looks like a GitHub repo - switched tabs"); } }; }
}
function pickFile(f) {
  if (!f) return;
  if (!f.name.toLowerCase().endsWith(".zip")) return toast("Please choose a .zip file", true);
  state.file = f; $("#dropTxt").textContent = `${f.name} · ${(f.size / 1048576).toFixed(1)} MB`;
}
function setProfile(id) { state.profile = id; $$(".profile").forEach((p) => p.classList.toggle("on", p.dataset.profile === id)); }

async function launch() {
  const btn = $("#launch"); btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Launching…`;
  try {
    const skip = ($("#skipTools").value || "").split(",").map((s) => s.trim()).filter(Boolean);
    const authRaw = $("#authHeader").value.trim(), auth = {};
    if (authRaw.includes(":")) { const i = authRaw.indexOf(":"); auth[authRaw.slice(0, i).trim()] = authRaw.slice(i + 1).trim(); }
    let res;
    if (state.tab === "zip") {
      if (!state.file) throw new Error("Choose a ZIP file first");
      const fd = new FormData(); fd.append("file", state.file); fd.append("profile", state.profile);
      const adv = $("#advLlmUrl").value.trim(); if (adv) fd.append("llm_endpoint", JSON.stringify({ url: adv }));
      res = await api("/api/scans/upload", { method: "POST", body: fd });
    } else {
      const target = ($("#target").value || "").trim();
      if (!target) throw new Error("Enter a target first");
      const body = { target, profile: state.profile, skip_tools: skip, auth_headers: auth, cloud_provider: $("#cloud").value || null };
      if (state.tab === "llm") {
        let tpl; try { tpl = JSON.parse($("#bodyTpl").value); } catch { throw new Error("Body template must be valid JSON"); }
        body.llm_endpoint = { url: target, body_template: tpl, response_path: $("#respPath").value.trim() || "reply" };
        body.kind = "url";
      } else {
        body.kind = state.tab;
        const adv = $("#advLlmUrl").value.trim(); if (adv) body.llm_endpoint = { url: adv };
      }
      res = await api("/api/scans", { method: "POST", json: body });
    }
    fxFlash();
    location.hash = `#/scan/${res.id}`;
  } catch (e) {
    let msg = e.message;
    if (e.status === 403 && e.data?.detail?.error) msg = e.data.detail.error;
    toast(msg, true);
    btn.disabled = false; btn.innerHTML = `Launch scan <span aria-hidden="true">→</span>`;
  }
}

// ------------------------------------------------------------------ SCAN (live + results)
const TOOL_ICON = { code: "🧬", web: "🌐", network: "📡", ai: "🤖", cloud: "☁️", other: "🔧" };
let blipsDrawn = 0;

async function renderScan(id) {
  blipsDrawn = 0;
  view.innerHTML = `
    <div class="scan-head">
      <div><h2 id="sTarget">Loading…</h2><div class="sub" id="sSub"></div></div>
      <div style="display:flex;align-items:center;gap:10px">
        <button class="btn stop-btn" id="stopBtn" style="display:none">⏹ Stop scan</button>
        <div class="timer" id="timer">00:00</div>
      </div>
    </div>
    <div class="card stepper" id="stepper">
      ${Object.entries(STAGE_LABEL).map(([k, v], i, a) => `<div class="step" data-stage="${k}"><div class="node">${i + 1}</div><small>${v}</small></div>${i < a.length - 1 ? '<div class="link"><i></i></div>' : ""}`).join("")}
    </div>
    <div class="live-grid" id="live">
      <div class="card radar-card">
        <div class="radar" id="radar"><div class="sweep"></div><div class="radar-center"><div><b id="rCount">0</b><span>findings</span></div></div></div>
        <div class="counters">${SEVS.map((s) => `<div class="counter" id="c-${s}" style="--c:var(--sev-${s})"><b style="color:var(--sev-${s})">0</b><small>${s}</small></div>`).join("")}</div>
        <div class="ticker" id="ticker"></div>
      </div>
      <div class="card"><h3>Tools</h3><div class="tools-grid" id="tools"></div>
        <div class="terminal" id="term" aria-live="off"></div></div>
    </div>
    <div id="results"></div>`;
  const stopBtn = $("#stopBtn");
  stopBtn.onclick = async () => {
    if (!confirm("Stop this scan? Any running tools will be terminated.")) return;
    stopBtn.disabled = true; stopBtn.innerHTML = `<span class="spinner"></span> Stopping…`;
    try { await api(`/api/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }); toast("Stopping scan — terminating running tools…"); }
    catch (e) { toast(e.message, true); stopBtn.disabled = false; stopBtn.innerHTML = "⏹ Stop scan"; }
  };
  let startedAt = null;
  clockTimer = setInterval(() => {
    if (!startedAt) return;
    const s = Math.max(0, Math.floor(Date.now() / 1000 - startedAt));
    $("#timer").textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  }, 500);
  let shownLogs = 0, finished = false;
  const tick = async () => {
    let d;
    try { d = await api(`/api/scans/${encodeURIComponent(id)}`); } catch (e) { $("#sTarget").textContent = "Scan not found"; clearInterval(pollTimer); return; }
    const p = d.progress || {};
    startedAt = p.started_at || startedAt;
    $("#sTarget").textContent = d.target;
    $("#sSub").innerHTML = `${esc(d.kind)} · ${esc(d.profile)} profile · <span class="status ${esc(d.status)}">${esc(d.status)}</span> · id ${esc(d.id)}`;
    const active = d.status === "running" || d.status === "queued" || d.status === "cancelling";
    stopBtn.style.display = active ? "" : "none";
    if (d.status === "cancelling") { stopBtn.disabled = true; stopBtn.innerHTML = `<span class="spinner"></span> Stopping…`; }
    updateStepper(p.stage || d.stage, d.status);
    updateTools(p.tools || {});
    updateCounts(p.counts || {});
    updateBlips(p.findings_preview || []);
    const logs = p.logs || [];
    const term = $("#term");
    if (term) {
      const atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
      $(".cursor", term)?.remove();
      for (const l of logs.slice(shownLogs)) {
        const div = document.createElement("div");
        div.className = "ln" + (l.msg.startsWith("──") ? " stage" : /ERROR|failed|Traceback/.test(l.msg) ? " err" : "");
        div.innerHTML = `<i>${String(l.t).padStart(6, " ")}s</i>${esc(l.msg)}`;
        term.appendChild(div);
      }
      shownLogs = logs.length;
      if (d.status === "running" || d.status === "queued") term.insertAdjacentHTML("beforeend", '<span class="cursor"></span>');
      if (atBottom) term.scrollTop = term.scrollHeight;
    }
    if ((d.status === "done" || d.status === "failed" || d.status === "cancelled") && !finished) {
      finished = true; clearInterval(pollTimer); $("#radar").classList.add("idle");
      stopBtn.style.display = "none";
      if (d.finished_at && startedAt) { const s = Math.round(new Date(d.finished_at).getTime() / 1000 - startedAt); $("#timer").textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; }
      clearInterval(clockTimer);
      if (d.status === "done") { toast("Scan complete ✨"); await renderResults(id); }
      else if (d.status === "cancelled") $("#results").innerHTML = `<div class="card" style="margin-top:18px"><h3>Scan stopped</h3><div class="muted">You stopped this scan. Any findings collected before stopping are not saved. Start a new scan when you're ready.</div><a class="btn" href="#/" style="margin-top:12px">New scan</a></div>`;
      else $("#results").innerHTML = `<div class="card" style="margin-top:18px;border-color:var(--fail)"><h3>Scan failed</h3><div>${esc(d.error)}</div></div>`;
    }
  };
  await tick();
  if (!finished) pollTimer = setInterval(tick, 1200);
}

function updateStepper(stage, status) {
  const keys = Object.keys(STAGE_LABEL);
  const idx = stage === "done" ? keys.length : keys.indexOf(stage);
  $$(".step").forEach((el, i) => {
    el.classList.toggle("done", i < idx || (status === "done"));
    el.classList.toggle("active", i === idx && status !== "done" && status !== "failed");
  });
  $$(".link").forEach((el, i) => el.classList.toggle("done", i < idx || status === "done"));
}

function updateTools(tools) {
  const grid = $("#tools"); if (!grid) return;
  const order = { running: 0, queued: 1, ok: 2, failed: 3, skipped: 4, not_installed: 5 };
  const entries = Object.entries(tools).sort((a, b) => (order[a[1].status] ?? 9) - (order[b[1].status] ?? 9) || a[0].localeCompare(b[0]));
  for (const [name, t] of entries) {
    let el = grid.querySelector(`[data-tool="${CSS.escape(name)}"]`);
    if (!el) { el = document.createElement("div"); el.dataset.tool = name; grid.appendChild(el); }
    if (el.dataset.st === t.status && el.dataset.n == (t.findings ?? "")) continue;
    el.dataset.st = t.status; el.dataset.n = t.findings ?? "";
    el.className = "tool " + t.status;
    const icon = t.status === "running" ? '<span class="spinner"></span>'
      : t.status === "ok" ? '<svg class="tick" viewBox="0 0 16 16"><path d="m3 8.5 3 3 7-7" fill="none" stroke="#34d399" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      : t.status === "failed" ? '<span style="color:var(--fail)">✕</span>' : "";
    const label = { running: "scanning…", queued: "queued", ok: `done in ${t.duration ?? "?"}s`, failed: t.reason || "failed",
      skipped: t.reason || "skipped", not_installed: "not installed" }[t.status] || t.status;
    el.title = t.reason || t.description || "";
    el.innerHTML = `<div class="cat">${TOOL_ICON[t.category] || "🔧"} ${esc(t.category || "")}</div><div class="name">${icon}${esc(name)}</div>
      <div class="st">${esc(label)}</div>${t.findings ? `<div class="num">${t.findings}</div>` : ""}`;
  }
  // keep DOM order in sync with sort (running first) using FLIP-free reorder
  entries.forEach(([name]) => grid.appendChild(grid.querySelector(`[data-tool="${CSS.escape(name)}"]`)));
}

function updateCounts(counts) {
  let total = 0;
  for (const s of SEVS) {
    const n = counts[s] || 0; total += n;
    const box = $(`#c-${s}`); if (!box) continue;
    const b = box.querySelector("b");
    if (Number(b.dataset.v || 0) !== n) { box.classList.remove("bump"); void box.offsetWidth; box.classList.add("bump"); countUp(b, n, 600); }
  }
  const rc = $("#rCount"); if (rc && Number(rc.dataset.v || 0) !== total) countUp(rc, total, 600);
}

function updateBlips(preview) {
  const radar = $("#radar"), ticker = $("#ticker"); if (!radar) return;
  for (const f of preview.slice(blipsDrawn)) {
    const h = hash32(f.title + f.tool), ang = (h % 360) * Math.PI / 180;
    const r = { critical: 0.25, high: 0.45, medium: 0.68, low: 0.82, info: 0.9 }[f.severity] ?? 0.8;
    const jitter = ((h >> 9) % 100) / 100 * 0.12;
    const b = document.createElement("div"); b.className = "blip";
    b.style.setProperty("--c", `var(--sev-${f.severity})`);
    b.style.left = `${50 + Math.cos(ang) * (r + jitter) * 46}%`; b.style.top = `${50 + Math.sin(ang) * (r + jitter) * 46}%`;
    b.title = f.title; radar.appendChild(b);
    if (f.severity === "critical" || f.severity === "high") {
      requestAnimationFrame(() => { const r = b.getBoundingClientRect(); if (r.width) FX.burst(r.left + r.width / 2, r.top + r.height / 2, 14, 3.5); });
    }
    const row = document.createElement("div");
    row.innerHTML = `${sevPill(f.severity)}<span>${esc(f.title.slice(0, 70))}</span>`;
    ticker.prepend(row); while (ticker.children.length > 5) ticker.lastChild.remove();
  }
  blipsDrawn = preview.length;
}

// ------------------------------------------------------------------ RESULTS
let result = null, filt = { sev: new Set(), verdict: new Set(), q: "", tool: "", owasp: "", showFp: false };

async function renderResults(id) {
  result = await api(`/api/scans/${encodeURIComponent(id)}/result`);
  filt = { sev: new Set(), verdict: new Set(), q: "", tool: "", owasp: "", showFp: false };
  const s = result.summary, c = s.counts;
  const riskColor = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", none: "var(--ok)" }[s.risk];
  const riskVal = { none: 0.06, low: 0.3, medium: 0.55, high: 0.78, critical: 0.96 }[s.risk];
  const total = SEVS.reduce((a, k) => a + c[k], 0) || 1;
  const tools = [...new Set(result.findings.flatMap((f) => f.sources))].sort();
  const dl = (fmt, label) => `<a class="btn" href="/api/scans/${encodeURIComponent(id)}/report.${fmt}${fmt === "html" ? "" : "?download=1"}" ${fmt === "html" ? 'target="_blank" rel="noopener"' : ""}>${label}</a>`;
  $("#results").innerHTML = `
  <div class="results">
    <div class="card risk-banner" style="--rc:${riskColor}">
      <div class="gauge">
        <svg viewBox="0 0 240 130" role="img" aria-label="Overall risk ${esc(s.risk)}">
          <path d="M20 120 A100 100 0 0 1 220 120" fill="none" stroke="var(--line)" stroke-width="16" stroke-linecap="round"/>
          <path id="gArc" d="M20 120 A100 100 0 0 1 220 120" fill="none" stroke="${riskColor}" stroke-width="16" stroke-linecap="round" pathLength="100" stroke-dasharray="100" stroke-dashoffset="100" style="transition: stroke-dashoffset 1.4s cubic-bezier(.2,.8,.2,1)"/>
          <line id="gNeedle" x1="120" y1="120" x2="120" y2="38" stroke="var(--ink)" stroke-width="3" stroke-linecap="round" style="transform-origin:120px 120px; transform: rotate(-90deg); transition: transform 1.4s cubic-bezier(.3,1.3,.5,1)"/>
          <circle cx="120" cy="120" r="7" fill="var(--ink)"/>
        </svg>
        <div class="lbl"><b>${esc(s.risk)}</b><span>overall risk</span></div>
      </div>
      <div>
        <h3 style="margin-bottom:8px">Executive summary</h3>
        <div class="summary">${esc(s.executive_summary)}</div>
        <div class="dl">${dl("html", "📄 VA report")}${dl("pdf", "⬇ VA PDF")}${result.audit ? `<a class="btn" href="/api/scans/${encodeURIComponent(id)}/report.audit" target="_blank" rel="noopener">📘 Audit report</a>` : ""}${dl("json", "{ } JSON")}${dl("sarif", "SARIF")}${result.meta.kind !== "url" ? dl("sbom", "SBOM") : ""}</div>
      </div>
    </div>
    <div class="stats">${SEVS.map((k) => `<div class="card stat clickable" data-sevtile="${k}" style="--c:var(--sev-${k})" title="Show ${k} findings"><b data-to="${c[k]}">0</b><small style="color:var(--sev-${k})">${k}</small></div>`).join("")}</div>
    ${accuracyPanel(s.accuracy)}
    <div class="card" style="margin-bottom:18px">
      <h3>Severity distribution · ${s.total_open} open${s.likely_false_positives ? ` · ${s.likely_false_positives} likely false positive(s)` : ""}</h3>
      <div class="sevbar">${SEVS.filter((k) => c[k]).map((k, i) => `<span style="--c:var(--sev-${k}); flex:${c[k]}; animation-delay:${i * 0.12}s" title="${k}: ${c[k]} (${Math.round(100 * c[k] / total)}%)"></span>`).join("") || '<span style="--c:var(--ok);flex:1"></span>'}</div>
      <div class="legend">${SEVS.map((k) => `<span><i style="--c:var(--sev-${k})"></i>${k} <b>${c[k]}</b></span>`).join("")}</div>
    </div>
    <div class="owasp-wrap">
      <div class="card"><h3>OWASP Top 10 · 2025</h3><div class="owasp-grid">${owaspCells("A")}</div></div>
      <div class="card"><h3>OWASP Top 10 for LLM apps · 2025</h3><div class="owasp-grid">${owaspCells("LLM")}</div></div>
    </div>
    ${auditTeaser(id)}
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px"><h3 style="margin:0">Findings</h3>
        <div class="vfilters">${Object.entries(VERDICT).map(([k, v]) => `<button class="chip vchip ${v.cls}" data-verdict="${k}">${v.icon} ${v.label}</button>`).join("")}</div>
      </div>
      <div class="filters" style="margin-top:12px">
        ${SEVS.map((k) => `<button class="chip" data-sev="${k}" style="--c:var(--sev-${k})">${k} · ${c[k]}</button>`).join("")}
        <select class="search" id="fTool"><option value="">All tools</option>${tools.map((t) => `<option>${esc(t)}</option>`).join("")}</select>
        <input class="search" id="fQ" placeholder="Search title, file, URL, CVE…">
        <label class="chip"><input type="checkbox" id="fFp" style="margin-right:6px">show false positives</label>
      </div>
      <div class="flist" id="flist"></div>
    </div>
    <div class="card" style="margin-top:18px"><h3>Tool runs</h3>
      <div class="tscroll"><table class="ttable"><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Time</th><th>Notes</th></tr>
      ${result.tool_runs.slice().sort((a, b) => a.tool.localeCompare(b.tool)).map((t) => `<tr><td><b>${esc(t.tool)}</b></td><td class="${t.status === "ok" ? "yes" : t.status === "failed" ? "no" : "muted"}">${esc(t.status.replace("_", " "))}</td><td>${t.findings}</td><td>${t.duration_s}s</td><td class="muted">${esc(t.reason)}</td></tr>`).join("")}
      </table></div></div>
  </div>`;
  requestAnimationFrame(() => {
    $("#gArc").style.strokeDashoffset = 100 - riskVal * 100;
    $("#gNeedle").style.transform = `rotate(${-90 + riskVal * 180}deg)`;
    $$(".stat b").forEach((b) => countUp(b, Number(b.dataset.to), 1100));
    animateRings($("#results"));
  });
  $$(".chip[data-sev]").forEach((ch) => ch.onclick = () => { const k = ch.dataset.sev; filt.sev.has(k) ? filt.sev.delete(k) : filt.sev.add(k); ch.classList.toggle("on"); drawFindings(); });
  // clicking a big severity tile filters to that severity and jumps to the findings list
  $$(".stat[data-sevtile]").forEach((tile) => tile.onclick = () => {
    const k = tile.dataset.sevtile; filt.sev = new Set([k]);
    $$(".chip[data-sev]").forEach((c) => c.classList.toggle("on", c.dataset.sev === k));
    drawFindings();
    $("#flist").scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "start" });
  });
  const toggleVerdict = (k) => { if (filt.verdict.has(k)) filt.verdict.delete(k); else filt.verdict.add(k);
    $$(`.vchip[data-verdict="${k}"]`).forEach((c) => c.classList.toggle("on", filt.verdict.has(k)));
    $$(`.acc-tile[data-verdict="${k}"]`).forEach((c) => c.classList.toggle("on", filt.verdict.has(k)));
    filt.showFp = filt.showFp || filt.verdict.has("false_positive"); const fp = $("#fFp"); if (fp) fp.checked = filt.showFp; drawFindings(); };
  $$(".vchip").forEach((ch) => ch.onclick = () => toggleVerdict(ch.dataset.verdict));
  $$(".acc-tile").forEach((ch) => ch.onclick = () => { toggleVerdict(ch.dataset.verdict); $("#flist").scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "start" }); });
  $("#fTool").onchange = (e) => { filt.tool = e.target.value; drawFindings(); };
  $("#fQ").oninput = (e) => { filt.q = e.target.value.toLowerCase(); drawFindings(); };
  $("#fFp").onchange = (e) => { filt.showFp = e.target.checked; drawFindings(); };
  $$(".ocell").forEach((cell) => cell.onclick = () => {
    filt.owasp = filt.owasp === cell.dataset.id ? "" : cell.dataset.id;
    $$(".ocell").forEach((x) => x.classList.toggle("sel", x.dataset.id === filt.owasp)); drawFindings();
    $("#flist").scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "start" });
  });
  drawFindings();
  setTimeout(() => $("#results .results")?.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth" }), 400);
}

function accuracyPanel(a) {
  if (!a) return "";
  const t = a.tiers || {};
  const tiles = [["verified", "Verified", "v-verified"], ["likely", "Likely", "v-likely"], ["uncertain", "Needs review", "v-uncertain"], ["false_positive", "False positive", "v-fp"]];
  return `<div class="card accuracy" style="margin-bottom:18px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <h3 style="margin:0">Accuracy &amp; confidence</h3>
      <div class="acc-gauge"><div class="ring" style="--p:${a.mean_confidence}"><b>${a.mean_confidence}%</b></div><span class="muted">mean confidence</span></div>
    </div>
    <div class="acc-tiles">${tiles.map(([k, label, cls]) => `<button class="acc-tile ${cls}" data-verdict="${k}"><b>${t[k] || 0}</b><small>${label}</small></button>`).join("")}</div>
    <div class="muted" style="font-size:12.5px;margin-top:10px">${a.high_confidence_pct}% of open findings are high-confidence · ${a.reviewed} reviewed by you.
      Each finding is scored from tool reliability, cross-tool agreement, exploit data and AI triage — open one to see why, and confirm or dismiss it.</div>
  </div>`;
}

function auditTeaser(id) {
  if (!result.audit) return "";
  const entries = Object.entries(result.audit);
  return `<div class="card" style="margin-bottom:18px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <h3 style="margin:0">Compliance audit</h3>
      <a class="btn" href="#/audit/${encodeURIComponent(id)}">Open full audit →</a>
    </div>
    <div class="fw-grid" style="margin-top:12px">${entries.map(([name, a]) => `<a href="#/audit/${encodeURIComponent(id)}" class="fw-badge-link">${fwBadge(name, a)}</a>`).join("")}</div>
  </div>`;
}

function fwBadge(name, a) {
  const score = a.score, posture = a.posture;
  const col = score == null ? "var(--muted)" : score >= 80 ? "var(--ok)" : score >= 50 ? "var(--sev-medium)" : "var(--fail)";
  return `<div class="fw-badge" title="${esc(a.desc)}">
    <div class="fw-ring" style="--p:${score || 0}; --c:${col}"><b>${score == null ? "–" : score + "%"}</b></div>
    <div class="fw-meta"><div class="fw-name">${esc(a.short)}</div><div class="muted" style="font-size:11px">${a.gaps} gap${a.gaps === 1 ? "" : "s"} · ${a.assessed}/${a.total} assessed</div></div>
  </div>`;
}

function owaspCells(prefix) {
  return Object.entries(result.coverage).filter(([k]) => k.startsWith(prefix)).map(([k, v], i) => {
    const hit = v.findings > 0, untested = !v.tested_by.length;
    return `<div class="ocell ${hit ? "hit" : ""} ${untested ? "untested" : ""}" data-id="${esc(k)}" style="--c:var(--sev-${v.max_severity || "info"}); animation-delay:${i * 0.04}s"
      title="${esc(v.name)} - ${v.findings} finding(s). ${untested ? "Not tested in this scan." : "Tested by: " + esc(v.tested_by.join(", "))}">
      <div class="id">${esc(k.split(":")[0])}</div><div class="nm">${esc(v.name)}</div><div class="ct">${v.findings || (untested ? "–" : "✓")}</div>
      <div class="tb">${untested ? "not tested" : v.tested_by.length + " tool" + (v.tested_by.length > 1 ? "s" : "")}</div></div>`;
  }).join("");
}

function drawFindings() {
  const list = $("#flist");
  const showFp = filt.showFp || filt.verdict.has("false_positive");
  const items = result.findings.filter((f) => (showFp || f.status === "open")
    && (!filt.sev.size || filt.sev.has(f.severity)) && (!filt.tool || f.sources.includes(filt.tool))
    && (!filt.verdict.size || filt.verdict.has(f.verdict))
    && (!filt.owasp || f.owasp.includes(filt.owasp) || f.owasp_llm.includes(filt.owasp))
    && (!filt.q || (f.title + " " + locText(f.location) + " " + f.cve.join(" ") + " " + f.cwe.join(" ") + " " + (f.frameworks || []).join(" ")).toLowerCase().includes(filt.q)));
  if (!items.length) { list.innerHTML = `<div class="empty">No findings match these filters ${result.findings.length ? "" : "- clean scan 🎉"}</div>`; return; }
  list.innerHTML = items.slice(0, 400).map((f, i) => `
    <div class="frow ${f.status !== "open" ? "fp" : ""} ${f.user_verdict ? "reviewed" : ""}" data-id="${esc(f.id)}" style="animation-delay:${Math.min(i, 25) * 0.025}s">
      <div>${sevPill(f.severity)}</div>
      <div><div class="t">${esc(f.title)}</div><div>${verdictPill(f)}${f.owasp.map((o) => `<span class="pill">${esc(o.split(":")[0])}</span>`).join("")}${f.owasp_llm.map((o) => `<span class="pill llm">${esc(o.split(":")[0])}</span>`).join("")}${f.kev ? '<span class="pill cve">CISA KEV</span>' : ""}${f.cve.slice(0, 2).map((v) => `<span class="pill cve">${esc(v)}</span>`).join("")}${f.user_verdict ? `<span class="pill gray">you: ${f.user_verdict === "confirmed" ? "confirmed" : "dismissed"}</span>` : ""}</div></div>
      <div class="loc" title="${esc(locText(f.location))}">${esc(locText(f.location))}</div>
      <div class="src">${esc(f.sources.join(", "))}</div>
    </div>`).join("") + (items.length > 400 ? `<div class="empty">Showing 400 of ${items.length}. Narrow the filters or download the full report.</div>` : "");
  $$(".frow", list).forEach((r) => r.onclick = () => openFinding(r.dataset.id));
}

// ------------------------------------------------------------------ drawer
function openFinding(fid) {
  const f = result.findings.find((x) => x.id === fid); if (!f) return;
  const l = f.location;
  $("#drawerBody").innerHTML = `
    ${sevPill(f.severity)} ${verdictPill(f)}
    <h2>${esc(f.title)}</h2>
    <div class="mono muted" style="font-size:12.5px;word-break:break-all">${esc(locText(l))}${l.method ? " · " + esc(l.method) : ""}</div>
    <div class="acc-box">
      <div class="acc-box-top"><span>Confidence this is real</span><b>${f.confidence_score}%</b></div>
      ${confMeter(f.confidence_score)}
      <ul class="acc-signals">${(f.accuracy_signals || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
      <div class="verdict-actions">
        <button class="btn ${f.user_verdict === "confirmed" ? "on-ok" : ""}" id="vConfirm">✓ Confirm (real)</button>
        <button class="btn ${f.user_verdict === "dismissed" ? "on-fp" : ""}" id="vDismiss">✕ Dismiss (false positive)</button>
        ${f.user_verdict ? `<button class="btn" id="vReset">reset</button>` : ""}
      </div>
    </div>
    <div style="margin-top:10px">${f.owasp.map((o) => `<span class="pill">${esc(o)}</span>`).join("")}${f.owasp_llm.map((o) => `<span class="pill llm">${esc(o)}</span>`).join("")}${f.cwe.map((w) => `<span class="pill gray">${esc(w)}</span>`).join("")}${f.cve.slice(0, 8).map((v) => `<span class="pill cve">${esc(v)}</span>`).join("")}${f.cvss ? `<span class="pill cve">CVSS ${esc(f.cvss)}</span>` : ""}${f.epss ? `<span class="pill cve">EPSS ${(f.epss * 100).toFixed(1)}%</span>` : ""}${f.kev ? '<span class="pill cve">CISA KEV</span>' : ""}</div>
    ${(f.frameworks || []).length ? `<div class="k">Maps to controls</div><div>${f.frameworks.map((x) => `<span class="pill fw">${esc(x)}</span>`).join("")}</div>` : ""}
    <div class="k">Reported by</div><div>${f.sources.map((s) => `<span class="pill gray">${esc(s)}</span>`).join("")} <span class="muted">· rule ${esc(f.rule_id || "-")}</span></div>
    ${f.description ? `<div class="k">Description</div><div>${esc(f.description).replace(/\n/g, "<br>")}</div>` : ""}
    ${f.evidence ? `<div class="k">Evidence</div><pre>${esc(f.evidence)}</pre>` : ""}
    ${f.remediation || f.fixed_version ? `<div class="k">How to fix</div><div>${esc(f.remediation)}${f.fixed_version ? ` <b>Fixed in ${esc(f.fixed_version)}</b>` : ""}</div>` : ""}
    ${f.guidance ? `<div class="k">Knowledge base (RAG)</div><div class="guidance">${md(f.guidance)}</div>` : ""}
    ${f.triage_note ? `<div class="k">AI triage</div><div class="muted">${esc(f.triage_note)}</div>` : ""}
    ${f.references.length ? `<div class="k">References</div>${f.references.slice(0, 6).map((u) => /^https?:\/\//.test(u) ? `<div style="word-break:break-all;font-size:13px"><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></div>` : "").join("")}` : ""}
    <div class="k">Ask AI</div>
    <div style="display:flex;gap:8px"><input class="search" id="askQ" value="Explain this finding and show me exactly how to fix it."><button class="btn" id="askBtn">✨ Ask</button></div>
    <div id="askOut"></div>`;
  $("#askBtn").onclick = () => askAI(fid);
  const setVerdict = async (verdict) => {
    try {
      const r = await api(`/api/scans/${encodeURIComponent(result.meta.scan_id)}/findings/${encodeURIComponent(fid)}/verdict`, { method: "POST", json: { verdict } });
      // update local result in place
      const idx = result.findings.findIndex((x) => x.id === fid);
      if (idx >= 0) result.findings[idx] = r.finding;
      result.summary = r.summary; result.audit = r.audit;
      toast(verdict === "confirmed" ? "Marked as a real finding ✓" : verdict === "dismissed" ? "Marked as a false positive" : "Verdict reset");
      openFinding(fid); // re-render drawer
      // refresh accuracy panel + audit teaser + list without full reload
      const acc = $(".accuracy"); if (acc) acc.outerHTML = accuracyPanel(result.summary.accuracy);
      drawFindings();
    } catch (e) { toast(e.message, true); }
  };
  $("#vConfirm").onclick = () => setVerdict(f.user_verdict === "confirmed" ? "" : "confirmed");
  $("#vDismiss").onclick = () => setVerdict(f.user_verdict === "dismissed" ? "" : "dismissed");
  if ($("#vReset")) $("#vReset").onclick = () => setVerdict("");
  $("#drawer").classList.add("open"); $("#drawer").setAttribute("aria-hidden", "false"); $("#scrim").classList.add("on");
  $("#drawer .drawer-inner").scrollTop = 0;
}
function closeDrawer() { $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); $("#scrim").classList.remove("on"); }
$("#drawerClose").onclick = closeDrawer; $("#scrim").onclick = closeDrawer;
addEventListener("keydown", (e) => e.key === "Escape" && closeDrawer());

async function askAI(fid) {
  const out = $("#askOut"), btn = $("#askBtn");
  btn.disabled = true; out.innerHTML = `<div class="ai-answer"><span class="spinner"></span> thinking… (local models on CPU can take a minute)</div>`;
  try {
    const r = await api(`/api/scans/${encodeURIComponent(result.meta.scan_id)}/findings/${encodeURIComponent(fid)}/ask`, { method: "POST", json: { question: $("#askQ").value } });
    const box = document.createElement("div"); box.className = "ai-answer"; out.innerHTML = ""; out.appendChild(box);
    const html = md(r.answer) + (r.model ? `<div class="muted" style="font-size:11.5px;margin-top:8px">${esc(r.model)}</div>` : r.llm === false ? `<div class="muted" style="font-size:11.5px;margin-top:8px">No LLM configured - showing knowledge-base guidance.</div>` : "");
    if (REDUCED) box.innerHTML = html;
    else { // reveal word by word
      const tmp = document.createElement("div"); tmp.innerHTML = html; const full = tmp.innerHTML; let i = 0;
      const step = () => { i = Math.min(full.length, i + 18); const cut = full.slice(0, i); box.innerHTML = cut.lastIndexOf("<") > cut.lastIndexOf(">") ? cut.slice(0, cut.lastIndexOf("<")) : cut; if (i < full.length) requestAnimationFrame(step); else box.innerHTML = full; };
      step();
    }
  } catch (e) { out.innerHTML = `<div class="ai-answer" style="color:var(--fail)">${esc(e.message)}</div>`; }
  btn.disabled = false;
}

// ------------------------------------------------------------------ HISTORY
async function renderHistory() {
  view.innerHTML = `<h1 class="page-title">Scan history</h1><div class="muted">Every scan and its report, newest first.</div><div class="hist" id="hist"></div>`;
  try {
    const { scans } = await api("/api/scans");
    if (!scans.length) { $("#hist").innerHTML = `<div class="card empty">No scans yet. <a href="#/">Start one →</a></div>`; return; }
    $("#hist").innerHTML = scans.map((s, i) => {
      const c = s.summary?.counts || {}, tot = SEVS.reduce((a, k) => a + (c[k] || 0), 0) || 1;
      return `<a class="card hcard" href="#/scan/${encodeURIComponent(s.id)}" style="animation-delay:${i * 0.04}s">
        <div class="status ${esc(s.status)}">${esc(s.status)}${s.status === "running" ? " · " + esc(s.stage) : ""}</div>
        <div class="tg">${esc(s.target)}</div>
        <div class="muted" style="font-size:12.5px">${esc(s.kind)} · ${esc(s.profile)} · ${new Date(s.created_at).toLocaleString()}</div>
        ${s.status === "done" ? `<div class="sevbar" style="height:8px;margin-top:12px">${SEVS.filter((k) => c[k]).map((k) => `<span style="--c:var(--sev-${k});flex:${c[k]}"></span>`).join("") || '<span style="--c:var(--ok);flex:1"></span>'}</div>
        <div class="legend" style="font-size:11.5px">${SEVS.slice(0, 4).map((k) => `<span><i style="--c:var(--sev-${k})"></i>${c[k] || 0} ${k}</span>`).join("")}</div>` : s.error ? `<div class="muted" style="font-size:12.5px;margin-top:8px;color:var(--fail)">${esc(s.error.slice(0, 140))}</div>` : ""}
      </a>`; }).join("");
  } catch (e) { toast(e.message, true); }
}

// ------------------------------------------------------------------ TOOLS & SCOPE
async function renderTools() {
  view.innerHTML = `<h1 class="page-title">Tools &amp; scope</h1><div class="muted">What's installed, which AI model is active, and which hosts may be scanned.</div>
    <div class="owasp-wrap" style="margin-top:20px"><div class="card" id="tcard"><h3>Scanners</h3>Loading…</div>
    <div><div class="card" id="aicard" style="margin-bottom:18px"><h3>AI</h3>Loading…</div><div class="card" id="scard"><h3>Scope</h3>Loading…</div>
    <div class="card" style="margin-top:18px"><h3>API key (only if VULNSCAN_API_KEY is set)</h3><div style="display:flex;gap:8px"><input class="search" id="akey" type="password" placeholder="X-API-Key" value="${esc(apiKey())}"><button class="btn" id="akeySave">Save</button></div></div></div></div>`;
  $("#akeySave").onclick = () => { try { localStorage.setItem("vulnscan_api_key", $("#akey").value); toast("Saved"); } catch { toast("Browser storage unavailable", true); } };
  try {
    const t = await api("/api/tools");
    $("#tcard").innerHTML = `<h3>Scanners</h3><div class="tscroll"><table class="ttable"><tr><th>Tool</th><th>Installed</th><th>Profile</th><th>What it does</th></tr>${t.tools.map((x) =>
      `<tr><td><b>${esc(x.name)}</b><div class="muted" style="font-size:11.5px">${esc(x.category)}</div></td><td class="${x.installed ? "yes" : "no"}">${x.installed ? "yes" : "no"}</td><td>${esc(x.min_profile)}+</td><td class="muted" style="font-size:13px">${esc(x.description)}</td></tr>`).join("")}</table></div>`;
    const l = t.llm;
    $("#aicard").innerHTML = `<h3>AI</h3><table class="ttable">
      <tr><th>LLM provider</th><td>${esc(l.provider)}</td></tr><tr><th>Model</th><td>${esc(l.model || "-")}</td></tr>
      <tr><th>Ready</th><td class="${l.ready ? "yes" : "no"}">${l.ready ? "yes" : "no"} <span class="muted">${esc(l.hint || l.error || "")}</span></td></tr>
      <tr><th>Prompt Guard</th><td>${esc(t.prompt_guard.model)}<br><span class="${t.prompt_guard.hf_token_set ? "yes" : "no"}">${t.prompt_guard.hf_token_set ? "HF_TOKEN set" : "HF_TOKEN missing"}</span></td></tr></table>`;
    const sc = await api("/api/scope");
    $("#scard").innerHTML = `<h3>Scope</h3><div class="muted" style="font-size:13px;margin-bottom:8px">Always allowed (ALLOWED_TARGETS):</div>
      <div>${sc.allowed_targets.map((h) => `<span class="pill gray">${esc(h)}</span>`).join("")}</div>
      <div class="muted" style="font-size:13px;margin:12px 0 8px">Verified hosts:</div><div>${sc.verified_hosts.map((h) => `<span class="pill">${esc(h)}</span>`).join("") || '<span class="muted">none</span>'}</div>
      <div class="k" style="margin-top:16px;font-weight:700;font-size:12.5px">Verify a domain you own</div>
      <div style="display:flex;gap:8px;margin-top:6px"><input class="search" id="vhost" placeholder="example.com"><button class="btn" id="vbtn">Check</button></div><div id="vout" style="margin-top:10px;font-size:13px"></div>`;
    $("#vbtn").onclick = async () => {
      const h = $("#vhost").value.trim().toLowerCase(); if (!h) return;
      try { const r = await api(`/api/verify/${encodeURIComponent(h)}`, { method: "POST" });
        $("#vout").innerHTML = r.verified ? `<span class="yes">✓ ${esc(h)} verified - you can scan it now.</span>`
          : `<div>Not verified yet. Do <b>one</b> of these, then click Check again:</div><ul>${r.options.map((o) => `<li class="mono" style="font-size:12px;word-break:break-all">${esc(o)}</li>`).join("")}</ul>`;
      } catch (e) { toast(e.message, true); }
    };
  } catch (e) { toast(e.message, true); }
}

// ------------------------------------------------------------------ AUDIT
async function renderAuditHome() {
  view.innerHTML = `<h1 class="page-title">Compliance Audit</h1>
    <div class="muted" style="max-width:720px">Audit a GitHub repo, a ZIP or a website against security &amp; compliance frameworks —
      OWASP ASVS, NIST CSF, CIS Controls, ISO 27001, PCI DSS, SOC 2, GDPR and HIPAA. An audit runs the same deep scan,
      then maps every finding to the controls it affects and scores your posture per framework.</div>
    <div class="card" style="margin-top:20px"><h3>Audit an existing scan</h3><div id="auditList" class="muted">Loading…</div></div>
    <div class="card" style="margin-top:18px"><h3>Or start a new audit scan</h3>
      <div class="muted" style="margin-bottom:10px">Runs a standard scan, then builds the audit.</div>
      <a class="btn primary" href="#/">+ New scan</a></div>`;
  try {
    const { scans } = await api("/api/scans");
    const done = scans.filter((s) => s.status === "done");
    $("#auditList").innerHTML = done.length ? `<div class="hist">${done.map((s) => `<a class="card hcard" href="#/audit/${encodeURIComponent(s.id)}"><div class="tg">${esc(s.target)}</div><div class="muted" style="font-size:12.5px">${esc(s.kind)} · ${new Date(s.created_at).toLocaleString()}</div><div class="btn" style="margin-top:10px">View audit →</div></a>`).join("")}</div>`
      : `No completed scans yet. <a href="#/">Run one first →</a>`;
  } catch (e) { $("#auditList").textContent = e.message; }
}

const POSTURE_COL = { strong: "var(--ok)", fair: "var(--sev-medium)", weak: "var(--fail)", "insufficient-data": "var(--muted)" };
async function renderAudit(id) {
  view.innerHTML = `<div class="muted">Loading audit…</div>`;
  let r;
  try { r = await api(`/api/scans/${encodeURIComponent(id)}/result`); }
  catch (e) { view.innerHTML = `<div class="card">Audit not available: ${esc(e.message)}. <a href="#/audit">Back</a></div>`; return; }
  if (!r.audit) { view.innerHTML = `<div class="card">This scan predates the audit feature. Re-run the scan to generate an audit. <a href="#/audit">Back</a></div>`; return; }
  const frameworks = Object.entries(r.audit);
  const overall = Math.round(frameworks.filter(([, a]) => a.score != null).reduce((t, [, a]) => t + a.score, 0) / (frameworks.filter(([, a]) => a.score != null).length || 1));
  view.innerHTML = `
    <div class="scan-head"><div><h2>Compliance Audit</h2><div class="sub">${esc(r.meta.target)} · ${esc(r.meta.kind)} · ${(r.meta.finished_at || "").slice(0, 10)}</div></div>
      <a class="btn" href="#/scan/${encodeURIComponent(id)}">← Findings view</a></div>
    <div class="card audit-overall">
      <div class="acc-gauge"><div class="ring big" style="--p:${overall}"><b>${overall}%</b></div><span class="muted">overall posture</span></div>
      <div><h3 style="margin:0 0 6px">${frameworks.reduce((t, [, a]) => t + a.gaps, 0)} control gaps across ${frameworks.length} frameworks</h3>
        <div class="muted" style="font-size:13.5px">Each framework is scored on the controls this scan could assess. Gaps are controls with at least one open finding.
        Controls we can't judge automatically (physical, HR, governance) are marked <b>not assessed</b> — they still need a human auditor.</div>
        <div class="dl"><a class="btn primary" href="/api/scans/${encodeURIComponent(id)}/report.audit" target="_blank" rel="noopener">📘 Audit report (HTML)</a><a class="btn" href="/api/scans/${encodeURIComponent(id)}/report.audit_pdf?download=1">⬇ Audit report (PDF)</a><a class="btn" href="/api/scans/${encodeURIComponent(id)}/report.html" target="_blank" rel="noopener">VA report</a><a class="btn" href="/api/scans/${encodeURIComponent(id)}/report.json?download=1">{ } JSON</a></div>
      </div>
    </div>
    <div class="fw-cards">${frameworks.map(([name, a]) => `
      <div class="card fw-card" style="--c:${POSTURE_COL[a.posture]}">
        <div class="fw-card-head"><div><div class="fw-card-name">${esc(name)}</div><div class="muted" style="font-size:12px">${esc(a.desc)}</div></div>
          <div class="fw-ring big" style="--p:${a.score || 0}; --c:${POSTURE_COL[a.posture]}"><b>${a.score == null ? "–" : a.score + "%"}</b></div></div>
        <div class="fw-stat-row"><span class="gap">${a.gaps} gaps</span><span class="pass">${a.passed} pass</span><span class="muted">${a.total - a.assessed} not assessed</span></div>
        <div class="controls">${a.controls.map((ct) => `
          <div class="control ${ct.status}" ${ct.findings.length ? `data-fids='${esc(JSON.stringify(ct.findings.map((x) => x.id)))}'` : ""}>
            <div class="control-head"><span class="cstat"></span><b>${esc(ct.id)}</b> ${esc(ct.title)}
              ${ct.status === "gap" ? `<span class="pill cve" style="margin-left:auto">${ct.finding_count} finding${ct.finding_count === 1 ? "" : "s"}</span>` : ct.status === "pass" ? `<span class="pill" style="margin-left:auto;background:rgba(52,211,153,.14);color:#6ee7b7">pass</span>` : `<span class="pill gray" style="margin-left:auto">not assessed</span>`}</div>
            <div class="control-sum muted">${esc(ct.summary)}</div>
          </div>`).join("")}</div>
      </div>`).join("")}</div>`;
  // clicking a gap control jumps to those findings
  $$(".control[data-fids]").forEach((el) => el.onclick = () => {
    const ids = JSON.parse(el.dataset.fids);
    location.hash = `#/scan/${encodeURIComponent(id)}`;
    setTimeout(() => { const first = ids[0]; if (first) { const row = document.querySelector(`.frow[data-id="${first}"]`); if (row) { row.scrollIntoView({ behavior: "smooth", block: "center" }); row.click(); } } }, 900);
  });
  revealInit();
  requestAnimationFrame(() => animateRings());
}

// ------------------------------------------------------------------ in-app assistant
const assist = { open: false, history: [], busy: false };
function assistScanId() { const h = location.hash; const m = h.match(/#\/(scan|audit)\/(.+)/); return m ? decodeURIComponent(m[2]) : null; }
function toggleAssist(force) {
  assist.open = force === undefined ? !assist.open : force;
  $("#assistant").classList.toggle("open", assist.open);
  $("#assistant").setAttribute("aria-hidden", String(!assist.open));
  $("#assistBtn").classList.toggle("hidden", assist.open);
  if (assist.open) { setTimeout(() => $("#assistText").focus(), 100); if (!assist.history.length) assistGreet(); }
}
function assistGreet() {
  const sid = assistScanId();
  assistAppend("assistant", `Hi, I'm **VulnGuard** — your security & audit assistant.${sid ? " I can see your current scan." : ""}\n\nAsk me things like:\n- *What does this finding mean and how do I fix it?*\n- *Which of my findings are false positives?*\n- *Am I PCI DSS compliant? What are the gaps?*\n- *Explain prompt injection / CWE-89 / OWASP A01.*`);
}
function assistAppend(role, content) {
  const log = $("#assistLog");
  const el = document.createElement("div");
  el.className = "amsg " + role;
  el.innerHTML = role === "assistant" ? `<div class="abody">${md(content)}</div>` : `<div class="abody">${esc(content)}</div>`;
  log.appendChild(el); log.scrollTop = log.scrollHeight;
  return el;
}
async function assistSubmit(e) {
  e && e.preventDefault();
  if (assist.busy) return;
  const text = $("#assistText").value.trim();
  if (!text) return;
  $("#assistText").value = "";
  assistAppend("user", text);
  const priorHistory = assist.history.slice(-8); // history BEFORE this message
  assist.history.push({ role: "user", content: text });
  assist.busy = true; $("#assistSend").disabled = true;
  const thinking = assistAppend("assistant", "");
  thinking.querySelector(".abody").innerHTML = `<span class="spinner"></span> thinking…`;
  const patience = setTimeout(() => { const b = thinking.querySelector(".abody"); if (b) b.innerHTML = `<span class="spinner"></span> thinking… <span class="muted" style="font-size:11px">(a local model on CPU can take up to a minute for the first reply)</span>`; }, 4000);
  try {
    const r = await api("/api/chat", { method: "POST", json: { message: text, scan_id: assistScanId(), history: priorHistory }, timeoutMs: 200000 });
    clearTimeout(patience);
    thinking.querySelector(".abody").innerHTML = md(r.answer) + (r.llm === false ? `<div class="muted" style="font-size:11px;margin-top:6px">No AI model configured — showing knowledge-base guidance.</div>` : r.sources && r.sources.length ? `<div class="asrc">sources: ${r.sources.slice(0, 4).map((x) => esc(x)).join(" · ")}</div>` : "");
    assist.history.push({ role: "assistant", content: r.answer });
  } catch (err) {
    clearTimeout(patience);
    thinking.querySelector(".abody").innerHTML = `<span style="color:var(--fail)">⚠ ${esc(err.message || "request failed")}</span><div class="muted" style="font-size:11px;margin-top:4px">If this persists, check the API is running and the model is pulled (<code>docker compose logs -f ollama-pull</code>).</div>`;
  }
  $("#assistLog").scrollTop = $("#assistLog").scrollHeight;
  assist.busy = false; $("#assistSend").disabled = false; $("#assistText").focus();
}
$("#assistBtn").onclick = () => toggleAssist(true);
$("#assistClose").onclick = () => toggleAssist(false);
$("#assistForm").onsubmit = assistSubmit;
addEventListener("keydown", (e) => { if (e.key === "Escape" && assist.open) toggleAssist(false); });

// ------------------------------------------------------------------ tilt + cursor glare on glass panels
(function tiltGlare() {
  if (REDUCED || matchMedia("(hover: none)").matches) return;
  const SEL = ".card,.profile,.feature,.hcard,.stat,.tool,.ocell";
  let active = null;
  document.addEventListener("pointerover", (e) => {
    const el = e.target.closest(SEL);
    if (el && el !== active) { if (active) active.style.transform = ""; active = el; active.classList.add("tiltable"); }
  });
  document.addEventListener("pointermove", (e) => {
    if (!active) return;
    const r = active.getBoundingClientRect();
    if (r.width === 0) return;
    const x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
    if (x < 0 || x > 1 || y < 0 || y > 1) { active.style.transform = ""; active = null; return; }
    active.style.setProperty("--mx", (x * 100).toFixed(1) + "%");
    active.style.setProperty("--my", (y * 100).toFixed(1) + "%");
    const max = active.classList.contains("card") ? 1.2 : 2;
    active.style.transform = `perspective(900px) rotateY(${((x - .5) * 2 * max).toFixed(2)}deg) rotateX(${(-(y - .5) * 2 * max).toFixed(2)}deg)`;
  }, { passive: true });
  document.addEventListener("pointerout", (e) => {
    if (active && e.target.closest(SEL) === active && !active.contains(e.relatedTarget)) { active.style.transform = ""; active = null; }
  });
})();

// ------------------------------------------------------------------ hero orb parallax
addEventListener("pointermove", (e) => {
  const orb = document.getElementById("orb");
  if (!orb || REDUCED) return;
  const dx = (e.clientX / innerWidth - .5), dy = (e.clientY / innerHeight - .5);
  orb.style.transform = `translate(${(dx * 46).toFixed(1)}px, ${(dy * 40).toFixed(1)}px)`;
}, { passive: true });

// ------------------------------------------------------------------ scroll reveal
const revealIO = REDUCED ? null : new IntersectionObserver((entries) => {
  for (const en of entries) if (en.isIntersecting) { en.target.classList.add("in"); revealIO.unobserve(en.target); }
}, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });
function revealInit() {
  if (!revealIO) return;
  for (const el of $$("#view .card, #view .feature, #view .risk-banner")) {
    if (!el.classList.contains("reveal") && !el.classList.contains("in")) { el.classList.add("reveal"); revealIO.observe(el); }
  }
  // safety: never leave content hidden if the observer misses (e.g. off-screen renders)
  setTimeout(() => $$("#view .reveal:not(.in)").forEach((el) => { const r = el.getBoundingClientRect(); if (r.top < innerHeight) el.classList.add("in"); }), 1400);
}
new MutationObserver(() => revealInit()).observe(view, { childList: true, subtree: true });

refreshHealth(); setInterval(refreshHealth, 30000);
route();
