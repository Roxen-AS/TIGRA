// Analyst console: alert queue -> live investigation (SSE) -> case record, actions + approvals, SAR, graph.
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const money = (x) => "$" + Number(x || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
};

const state = { alerts: [], current: null, filter: "all", answer: null, log: [], points: [], es: null };

// ---------------------------------------------------------------- theme
try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
$("#theme").onclick = () => {
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  const cur = document.documentElement.dataset.theme || (dark ? "dark" : "light");
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("theme", next); } catch {}
};

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.add("hidden"), 3500);
}

// ---------------------------------------------------------------- queue
async function loadHealth() {
  try {
    const h = await api("/api/health");
    $("#backend").textContent = `graph: ${h.backend}`; $("#backend").classList.add("on");
    $("#llm").textContent = h.llm ? `LLM: ${h.model}` : "LLM: templates";
    if (h.llm) $("#llm").classList.add("on");
  } catch (e) { $("#backend").textContent = "backend offline"; }
}

async function loadAlerts() {
  state.alerts = await api("/api/alerts");
  renderAlerts();
}

function renderAlerts() {
  const f = state.filter;
  const list = state.alerts.filter((a) => f === "all" || (f === "pending" ? !a.result : a.result?.verdict === f));
  $("#alerts").innerHTML = list.map((a) => {
    const r = a.result;
    const trig = { risk_score: "score " + (a.risk_score || ""), customer_report: "customer", analyst_request: "analyst" }[a.trigger_type];
    return `<li data-id="${esc(a.case_id)}" class="${state.current === a.case_id ? "active" : ""}">
      <span class="id">${esc(a.case_id)}</span>
      ${r ? `<span class="chip ${esc(r.verdict)}">${esc(r.verdict)} ${Math.round(r.fraud_probability * 100)}%</span>` : `<span class="chip">new</span>`}
      <span class="meta">${esc(trig)} · ${esc(a.card_id)} · ${esc(a.opened_at.slice(0, 10))}${r && r.pattern !== "none" ? " · " + esc(r.pattern) : ""}</span></li>`;
  }).join("") || `<li class="meta">No alerts in this filter.</li>`;
}
$("#alerts").onclick = (e) => { const li = e.target.closest("li[data-id]"); if (li) openCase(li.dataset.id); };
$("#filters").onclick = (e) => {
  const b = e.target.closest("button"); if (!b) return;
  state.filter = b.dataset.f;
  document.querySelectorAll("#filters button").forEach((x) => x.classList.toggle("on", x === b));
  renderAlerts();
};

// ---------------------------------------------------------------- case view
async function openCase(id) {
  if (location.hash.slice(1) !== id) history.replaceState(null, "", "#" + id);
  state.current = id; renderAlerts();
  const a = state.alerts.find((x) => x.case_id === id);
  showHeader(a);
  if (a?.result) {
    const { answer, log, trace } = await api(`/api/cases/${id}`);
    state.log = log; state.points = [];
    $("#trace").innerHTML = "";
    (trace || []).filter((ev) => ev.type !== "done").forEach(onEvent);   // replay the stored trace instantly
    if (!trace?.length) $("#trace").innerHTML = `<li class="step">Stored investigation. Click “Re-investigate” to run it live.</li>`;
    renderAnswer(answer);
    const tab = new URLSearchParams(location.search).get("tab");
    if (tab) document.querySelector(`#tabs button[data-t="${CSS.escape(tab)}"]`)?.click();
  } else {
    investigate(id);
  }
}

function showHeader(a) {
  $("#empty").classList.add("hidden"); $("#case").classList.remove("hidden");
  $("#cId").textContent = a?.case_id || "";
  $("#cTrig").textContent = (a?.trigger_type || "").replace("_", " ");
  $("#cText").textContent = a?.trigger_text || "";
  $("#cStatus").textContent = ""; $("#cStatus").className = "chip hidden";
  ["#kP", "#kV", "#kE", "#kC"].forEach((s) => ($(s).textContent = "–"));
  ["#kPat", "#kN", "#kL"].forEach((s) => ($(s).textContent = ""));
  drawGauge(null);
}

function investigate(id, url) {
  if (state.es) state.es.close();
  state.points = []; state.answer = null;
  $("#trace").innerHTML = ""; $("#live").classList.remove("hidden");
  ["summary", "actions", "evidence", "sar", "json"].forEach((t) => ($("#tab-" + t).innerHTML = ""));
  const es = new EventSource(url || `/api/investigate/${id}`);
  state.es = es;
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    onEvent(ev);
    if (ev.type === "done" || ev.type === "error") { es.close(); $("#live").classList.add("hidden"); if (!url) loadAlerts(); }
  };
  es.onerror = () => { es.close(); $("#live").classList.add("hidden"); };
}

function addTrace(cls, html) {
  const li = document.createElement("li"); li.className = cls; li.innerHTML = html;
  const tr = $("#trace"); tr.appendChild(li); tr.scrollTop = tr.scrollHeight;   // scroll the list, not the page
}

function onEvent(ev) {
  switch (ev.type) {
    case "start": state.points = [ev.prior]; drawSpark(state.points); drawGauge(ev.prior);
      addTrace("step", `Trigger: ${esc(ev.trigger.replace("_", " "))} <span class="p">prior ${ev.prior.toFixed(2)}</span>`); break;
    case "tool": addTrace("tool", `<span class="tname">${esc(ev.name)}</span> ${esc(ev.summary)} <span class="ms">${ev.ms}ms</span>`); break;
    case "evidence": state.points.push(ev.p); drawSpark(state.points); drawGauge(ev.p);
      addTrace(`ev ${ev.weight > 0 ? "pos" : "neg"}`, `<span class="w">${ev.weight > 0 ? "+" : ""}${ev.weight.toFixed(1)}</span> ${esc(ev.claim)} <span class="p">${ev.p.toFixed(2)}</span>`); break;
    case "step": addTrace("step", `${ev.step}. ${esc(ev.label)} <span class="p">${ev.p.toFixed(2)}${ev.settled ? " ✓" : ""}</span>`); break;
    case "actions": addTrace("step", `${ev.stage === "initial" ? "Initial" : "Final"} actions: ${ev.actions.map((a) => esc(a.action) + " [" + a.route + "]").join(", ")}`); break;
    case "request": addTrace("req", `Evidence request <b>${esc(ev.request)}</b>: ${esc(ev.assumed_response)}`); break;
    case "done": state.log = []; renderAnswer(ev.answer); toast(`${ev.answer.case_id}: ${ev.answer.case.verdict} (${ev.answer.tool_calls} tool calls, ${ev.answer.latency_s}s)`); break;
    case "error": addTrace("step", `Error: ${esc(ev.message)}`); toast(ev.message); break;
  }
}

function renderAnswer(ans) {
  state.answer = ans;
  const c = ans.case;
  $("#cStatus").textContent = c.status.replace("_", " "); $("#cStatus").className = "chip " + c.status;
  $("#kP").textContent = c.fraud_probability.toFixed(2); drawGauge(c.fraud_probability);
  $("#kV").innerHTML = `<span class="chip ${esc(c.verdict)}" style="font-size:15px">${esc(c.verdict)}</span>`;
  $("#kPat").textContent = c.pattern;
  $("#kE").textContent = money(c.exposure_usd); $("#kN").textContent = `${c.affected_txn_ids.length} txn · ${c.connected_card_ids.length} linked cards`;
  $("#kC").textContent = `${ans.tool_calls} calls`; $("#kL").textContent = `${ans.latency_s}s · ${ans.tokens} tokens`;

  $("#tab-summary").innerHTML = `
    <p class="summary">${esc(c.summary)}</p>
    ${c.pattern_description ? `<h4>Undocumented pattern</h4><p>${esc(c.pattern_description)}</p>` : ""}
    <div class="grid2">
      <div><h4>Case record</h4><dl class="facts">
        <dt>Graph case</dt><dd>${esc(c.graph_case_id || "not written")}</dd>
        <dt>First suspicious</dt><dd>${esc(c.first_suspicious_txn_id || "–")}</dd>
        <dt>Affected txns</dt><dd>${esc(c.affected_txn_ids.join(", ") || "–")}</dd>
        <dt>Linked cards</dt><dd>${esc(c.connected_card_ids.join(", ") || "–")}</dd>
        <dt>Device profiles</dt><dd>${esc(c.connected_device_profiles.join("; ") || "–")}</dd></dl></div>
      <div><h4>Case memory</h4><dl class="facts">
        <dt>Similar cases</dt><dd>${esc(c.similar_prior_cases.join(", ") || "–")}</dd>
        <dt>Stop reason</dt><dd style="font-family:inherit">${esc(ans.stop_reason)}</dd></dl></div>
    </div>`;

  const actList = (list, stage) => list.map((a) => {
    const done = state.log.find((l) => l.action === a.action && (l.event === "approve" || l.event === "reject"));
    const ctl = stage === "final" && a.route !== "auto"
      ? (done ? `<span class="approved">${esc(done.event)}d by ${esc(done.by)}</span>`
          : `<span class="approve"><button data-act="${esc(a.action)}" data-role="${a.route === "L1" ? "team lead" : "fraud manager"}" data-d="approve">Approve as ${a.route === "L1" ? "team lead" : "fraud manager"}</button><button data-act="${esc(a.action)}" data-role="${a.route === "L1" ? "team lead" : "fraud manager"}" data-d="reject">Reject</button></span>`)
      : a.route === "auto" ? `<span class="approved">${stage === "final" ? "executed by TIGRA" : ""}</span>` : "";
    return `<div class="act"><span class="name">${esc(a.action)}</span><span class="route ${a.route}">${a.route}</span>${ctl}<span class="reason">${esc(a.reason)}</span></div>`;
  }).join("");
  const nba = ans.next_best_actions;
  $("#tab-actions").innerHTML = `
    ${ans.evidence_requests.map((r) => `<div class="req"><b>${esc(r.type)}</b> after step ${r.asked_after_step}: ${esc(r.assumed_response)}</div>`).join("")}
    <div class="grid2"><div><h4>Initial (before evidence)</h4>${actList(nba.initial, "initial")}</div>
    <div><h4>Final (after evidence)</h4>${actList(nba.final, "final")}</div></div>
    <div class="changed"><b>What changed:</b> ${esc(nba.what_changed)}</div>`;

  $("#tab-evidence").innerHTML = c.evidence.map((e) => `<div class="evi"><span class="src">${esc(e.source)}</span>
    <div>${esc(e.claim)}<div class="ref">${esc(e.ref)}</div>${e.entity_ids.length ? `<div class="ids">${esc(e.entity_ids.slice(0, 16).join(", "))}${e.entity_ids.length > 16 ? " …" : ""}</div>` : ""}</div></div>`).join("");

  const s = ans.sar;
  $("#tab-sar").innerHTML = `<p><span class="chip ${s.file ? "fraud" : "legitimate"}">${s.file ? "File SAR (L2 approval)" : "No SAR"}</span> ${esc(s.reason)}</p>
    ${s.file ? `<div class="sar">${esc(s.narrative)}</div><dl class="facts" style="margin-top:10px">
      <dt>Subjects</dt><dd>${esc(s.subjects.join(", "))}</dd><dt>Total</dt><dd>${money(s.total_amount_usd)}</dd>
      <dt>Activity</dt><dd>${esc(s.activity_dates.join(" → "))}</dd></dl>` : ""}`;

  $("#tab-json").innerHTML = `<button id="dl" class="btn sm">Download ${esc(ans.case_id)}.json</button><pre>${esc(JSON.stringify(ans, null, 2))}</pre>`;
  $("#dl").onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(ans, null, 2)], { type: "application/json" }));
    Object.assign(document.createElement("a"), { href: url, download: `${ans.case_id}.json` }).click();
    URL.revokeObjectURL(url);
  };
  if (!$("#tab-graph").classList.contains("hidden")) drawGraph();
}

$("#tab-actions").onclick = async (e) => {
  const b = e.target.closest("button[data-act]"); if (!b || !state.answer) return;
  try {
    const r = await api(`/api/cases/${state.answer.case_id}/approve`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: b.dataset.act, role: b.dataset.role, decision: b.dataset.d }) });
    state.log = r.log; renderAnswer(state.answer); toast(`${b.dataset.act} ${b.dataset.d}d by ${b.dataset.role}`);
  } catch (err) { toast(err.message); }
};

$("#tabs").onclick = (e) => {
  const b = e.target.closest("button"); if (!b) return;
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("hidden", t.id !== "tab-" + b.dataset.t));
  if (b.dataset.t === "graph") drawGraph();
};
$("#rerun").onclick = () => state.current && investigate(state.current);
$("#runAll").onclick = async () => {
  const btn = $("#runAll"); btn.disabled = true;
  for (const a of state.alerts) {
    btn.textContent = `Running ${a.case_id}…`;
    await new Promise((res) => {
      const es = new EventSource(`/api/investigate/${a.case_id}`);
      es.onmessage = (m) => { const ev = JSON.parse(m.data); if (ev.type === "done" || ev.type === "error") { es.close(); res(); } };
      es.onerror = () => { es.close(); res(); };
    });
  }
  btn.disabled = false; btn.textContent = "Run all 20"; await loadAlerts(); toast("All 20 cases investigated and written to cases/");
};
$("#adhoc").onsubmit = (e) => {
  e.preventDefault();
  const id = $("#adhocTxn").value.trim(); const trig = $("#adhocTrig").value;
  if (!/^\d+$/.test(id)) return toast("TransactionID must be numeric");
  state.current = null; renderAlerts();
  showHeader({ case_id: `ADHOC-${id}`, trigger_type: trig, trigger_text: `Ad-hoc investigation of transaction ${id}` });
  investigate(null, `/api/investigate-txn?txn_id=${id}&trigger_type=${trig}`);
};

// ---------------------------------------------------------------- charts
function drawGauge(p) {
  const el = $("#gauge"); const col = p == null ? "var(--line)" : p >= 0.7 ? "var(--fraud)" : p <= 0.3 ? "var(--legit)" : "var(--unc)";
  const a = Math.PI * (1 - (p ?? 0)); const x = 60 + 48 * Math.cos(a), y = 62 - 48 * Math.sin(a);
  el.innerHTML = `<path d="M12 62 A48 48 0 0 1 108 62" fill="none" stroke="var(--soft)" stroke-width="10" stroke-linecap="round"/>
    ${p == null ? "" : `<path d="M12 62 A48 48 0 0 1 ${x.toFixed(1)} ${y.toFixed(1)}" fill="none" stroke="${col}" stroke-width="10" stroke-linecap="round"/>`}
    <line x1="60" y1="62" x2="60" y2="18" stroke="var(--muted)" stroke-dasharray="2 3" opacity=".5"/>`;
}

function drawSpark(pts) {
  const el = $("#spark");
  if (!pts.length) { el.innerHTML = ""; return; }
  const n = Math.max(pts.length - 1, 1);
  const xy = pts.map((p, i) => `${(i / n) * 300},${58 - p * 56}`).join(" ");
  el.innerHTML = `<line x1="0" x2="300" y1="${58 - 0.85 * 56}" y2="${58 - 0.85 * 56}" stroke="var(--fraud)" stroke-dasharray="3 3" opacity=".5"/>
    <line x1="0" x2="300" y1="${58 - 0.15 * 56}" y2="${58 - 0.15 * 56}" stroke="var(--legit)" stroke-dasharray="3 3" opacity=".5"/>
    <polyline points="${xy}" fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke"/>`;
}

const KIND = { customer: ["#7a5af8", 9], card: ["#f26b1d", 9], txn: ["#1570ef", 6], device: ["#d92d20", 8], case: ["#667085", 7], fraudcase: ["#079455", 9] };
async function drawGraph() {
  if (!state.answer?.case.graph_case_id) { $("#graphSvg").innerHTML = `<text x="20" y="30">Graph view is available for stored cases.</text>`; return; }
  const g = await api(`/api/graph/${state.answer.case_id}`);
  const svg = $("#graphSvg"); const W = svg.clientWidth || 700, H = 480;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  // deterministic start on a circle, focus card in the centre
  const N = g.nodes.map((n, i) => ({ ...n, x: n.focus ? W / 2 : W / 2 + Math.cos(i * 2.4) * 160, y: n.focus ? H / 2 : H / 2 + Math.sin(i * 2.4) * 140, vx: 0, vy: 0 }));
  const rep = 900 * Math.min(1, 30 / N.length);
  const idx = Object.fromEntries(N.map((n, i) => [n.id, i]));
  const E = g.edges.filter(([a, b]) => a in idx && b in idx).map(([a, b, t]) => [idx[a], idx[b], t]);
  for (let it = 0; it < 300; it++) {            // small force layout: repulsion + springs + centering
    for (let i = 0; i < N.length; i++) for (let j = i + 1; j < N.length; j++) {
      const dx = N[j].x - N[i].x, dy = N[j].y - N[i].y, d2 = dx * dx + dy * dy + 0.01, f = rep / d2;
      N[i].vx -= f * dx; N[i].vy -= f * dy; N[j].vx += f * dx; N[j].vy += f * dy;
    }
    for (const [a, b] of E) {
      const dx = N[b].x - N[a].x, dy = N[b].y - N[a].y, d = Math.hypot(dx, dy) || 1, f = (d - 70) * 0.03;
      N[a].vx += f * dx / d; N[a].vy += f * dy / d; N[b].vx -= f * dx / d; N[b].vy -= f * dy / d;
    }
    for (const n of N) {
      n.vx += (W / 2 - n.x) * 0.012; n.vy += (H / 2 - n.y) * 0.012;
      n.x = Math.max(20, Math.min(W - 130, n.x + n.vx * 0.5)); n.y = Math.max(20, Math.min(H - 20, n.y + n.vy * 0.5)); n.vx *= 0.6; n.vy *= 0.6;
    }
  }
  svg.innerHTML = E.map(([a, b, t]) => `<line x1="${N[a].x}" y1="${N[a].y}" x2="${N[b].x}" y2="${N[b].y}" stroke="var(--muted)" stroke-opacity=".35"><title>${esc(t)}</title></line>`).join("")
    + N.map((n) => { const [c, r] = KIND[n.kind] || ["#999", 6];
      return `<g><circle cx="${n.x}" cy="${n.y}" r="${n.focus || n.flagged ? r + 3 : r}" fill="${c}" stroke="${n.flagged || n.focus ? "var(--ink)" : "none"}" stroke-width="2"><title>${esc(n.profile || n.id)}</title></circle>
        <text x="${n.x + r + 3}" y="${n.y + 3}">${esc(n.label)}</text></g>`; }).join("");
  $("#graphLegend").innerHTML = Object.entries(KIND).map(([k, [c]]) => `<span><i style="background:${c}"></i>${k}</span>`).join("");
}

// Deep links: /#HHG-014 opens that case (shareable between analysts).
window.addEventListener("hashchange", () => { const id = location.hash.slice(1); if (id && id !== state.current) openCase(id); });
async function openCaseSafe(id) { try { await openCase(id); } catch (e) { toast(e.message); } }

loadHealth();
loadAlerts().then(() => { const id = location.hash.slice(1); if (id && state.alerts.some((a) => a.case_id === id)) openCaseSafe(id); });
