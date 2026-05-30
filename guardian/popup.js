// =============================================================================
// Guardian Shield — popup.js
// Renders:
//   1. Current page status (queries background.js for tab state)
//   2. Mode toggle (guided / enforcement)
//   3. Scan history log
// =============================================================================

document.addEventListener("DOMContentLoaded", async () => {

  // ── Get the current active tab ─────────────────────────────────────────────
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // ── Query background for this tab's latest scan state ─────────────────────
  // Background stores results in tabState Map and serves via "getState" message
  let pageState = null;
  try {
    const resp = await chrome.runtime.sendMessage({ type: "getState", tabId: tab?.id });
    pageState = resp?.state || null;
  } catch (_) {}

  renderStatus(pageState, tab);
  await refreshMode();
  await renderLog();

  // If apiStatus is still "checking", re-render after 5s with whatever we have.
  // This prevents the spinner from staying on screen forever if APIs are slow.
  if (pageState?.apiStatus === "checking") {
    setTimeout(async () => {
      try {
        const resp2 = await chrome.runtime.sendMessage({ type: "getState", tabId: tab?.id });
        const updated = resp2?.state || null;
        if (updated) renderStatus(updated, tab);
      } catch (_) {}
    }, 15000);
  }

  // ── Mode buttons ───────────────────────────────────────────────────────────
  document.getElementById("guidedBtn").onclick  = () =>
    chrome.storage.sync.set({ mode: "guided" },      refreshMode);
  document.getElementById("enforceBtn").onclick = () =>
    chrome.storage.sync.set({ mode: "enforcement" }, refreshMode);

  // ── Clear history ──────────────────────────────────────────────────────────
  document.getElementById("clearBtn").onclick = () =>
    chrome.storage.local.set({ activityLog: [] }, renderLog);
});


// =============================================================================
// RENDER CURRENT PAGE STATUS
// =============================================================================
function renderStatus(state, tab) {
  const el = document.getElementById("statusContent");

  // Pages like chrome:// or the new tab page — extension doesn't run there
  const url = tab?.url || "";
  if (!url.startsWith("http")) {
    el.innerHTML = `<div class="no-page">Guardian Shield does not run on this page type.</div>`;
    return;
  }

  // No state yet — scan hasn't come back yet (e.g. popup opened very fast)
  if (!state) {
    el.innerHTML = `
      <div class="api-checking">
        <div class="spinner"></div>
        <span>Scanning page…</span>
      </div>`;
    return;
  }

  const { score, stateKey, reasons, source, apiStatus, host } = normalizeState(state);

  // Score color
  const scoreColor =
    stateKey === "unsafe"  ? "#ef4444" :
    stateKey === "warning" ? "#f59e0b" : "#22c55e";

  // Badge label
  const badgeClass =
    stateKey === "unsafe"  ? "badge-unsafe"  :
    stateKey === "warning" ? "badge-warning" : "badge-safe";
  const badgeText =
    stateKey === "unsafe"  ? "UNSAFE"  :
    stateKey === "warning" ? "WARNING" : "SAFE";

  // Source label
  const sourceLabels = {
    safebrowsing: "Google Safe Browsing",
    virustotal:   "VirusTotal",
    heuristic:    "Local Analysis"
  };
  const sourceCls = {
    safebrowsing: "src-safebrowsing",
    virustotal:   "src-virustotal",
    heuristic:    "src-heuristic"
  };
  const sourceLabel = sourceLabels[source] || "Local Analysis";
  const sourceCssClass = sourceCls[source] || "src-heuristic";

  // Reasons — color code based on content
  const reasonsHTML = reasons.length > 0
    ? reasons.map(r => {
        const cls =
          r.includes("🚨") || r.includes("🦠") || r.includes("📤") ? "danger" :
          r.includes("⚠️") || r.includes("🎭") || r.includes("📧") ? "warn"  : "";
        return `<div class="reason-item ${cls}">${r}</div>`;
      }).join("")
    : `<div class="reason-item">No threats detected.</div>`;

  // API check in progress indicator
  const apiHTML = apiStatus === "checking"
    ? `<div class="api-checking" style="margin-top:8px">
         <div class="spinner"></div>
         <span>Checking threat databases (up to 5s)...</span>
       </div>`
    : "";

  el.innerHTML = `
    <div class="status-row">
      <div class="status-host">${host || new URL(tab.url).hostname}</div>
      <div class="status-badge ${badgeClass}">${badgeText}</div>
    </div>

    <div class="score-row">
      <div class="score-num" style="color:${scoreColor}">${score}</div>
      <div class="score-track">
        <div class="score-fill" style="width:${score}%;background:${scoreColor}"></div>
      </div>
      <div style="font-size:11px;color:var(--muted);flex-shrink:0">/100</div>
    </div>

    <span class="source-tag log-source-tag ${sourceCssClass}">
      Detected by: ${sourceLabel}
    </span>

    <div class="reasons-list">${reasonsHTML}</div>
    ${apiHTML}
  `;
}


// =============================================================================
// RENDER MODE
// =============================================================================
async function refreshMode() {
  const { mode } = await chrome.storage.sync.get({ mode: "guided" });

  document.getElementById("guidedBtn") .classList.toggle("active", mode === "guided");
  document.getElementById("enforceBtn").classList.toggle("active", mode === "enforcement");

  const desc = {
    guided:      "Warns you about threats and lets you decide. Recommended for daily use.",
    enforcement: "Automatically shows a block screen on unsafe pages. Use for strict protection."
  };
  document.getElementById("modeDesc").textContent = desc[mode] || "";
}


// =============================================================================
// RENDER SCAN LOG
// =============================================================================
async function renderLog() {
  const { activityLog: log } = await chrome.storage.local.get({ activityLog: [] });
  const summaryEl = document.getElementById("logSummary");
  const listEl    = document.getElementById("logList");

  if (log.length === 0) {
    summaryEl.textContent = "";
    listEl.innerHTML = `<div class="log-empty">No scans recorded yet.</div>`;
    return;
  }

  const high   = log.filter(e => e.severity === "High").length;
  const medium = log.filter(e => e.severity === "Medium").length;
  summaryEl.textContent =
    `${log.length} site(s) scanned: ${high} high risk, ${medium} medium risk`;

  // Build one log card
  function buildCard(entry, i) {
    const { score, stateKey, reasons, source } = normalizeState(entry);
    const severity = entry.severity || (score >= 50 ? "High" : score >= 20 ? "Medium" : "Low");
    const sevClass = severity === "High" ? "sev-high" : severity === "Medium" ? "sev-medium" : "sev-low";
    const sourceLabels = { safebrowsing: "Google Safe Browsing", virustotal: "VirusTotal", heuristic: "Local Analysis" };
    const sourceCls    = { safebrowsing: "src-safebrowsing", virustotal: "src-virustotal", heuristic: "src-heuristic" };
    const srcLabel = sourceLabels[source] || "Local Analysis";
    const srcCss   = sourceCls[source]    || "src-heuristic";

    const preview = reasons.slice(0, 2);
    const extra   = reasons.slice(2);

    const previewHTML = preview.length > 0
      ? preview.map(r => `<div class="log-reason-item">${r}</div>`).join("")
      : `<div class="log-reason-item muted">No issues found.</div>`;

    const extraHTML = extra.length > 0
      ? `<div class="log-extra" id="extra-${i}" style="display:none">
           ${extra.map(r => `<div class="log-reason-item">${r}</div>`).join("")}
         </div>
         <button class="see-more-btn" data-idx="${i}" data-total="${extra.length}">
           See ${extra.length} more details
         </button>`
      : "";

    return `
      <div class="log-item">
        <div class="log-meta">
          <span class="log-severity ${sevClass}">${severity} · ${score}/100</span>
          <span class="log-time">${entry.time || ""}</span>
        </div>
        <div class="log-host">${entry.host || ""}</div>
        <span class="log-source-tag ${srcCss}">${srcLabel}</span>
        <div class="log-reasons-wrap">${previewHTML}${extraHTML}</div>
      </div>`;
  }

  // Show only the most recent scan by default.
  // "Show all" reveals the full history.
  let showingAll = false;

  function renderItems() {
    const items = showingAll ? log : [log[0]];
    listEl.innerHTML =
      items.map((e, i) => buildCard(e, i)).join("") +
      (log.length > 1
        ? `<button class="show-all-btn" id="showAllBtn">
             ${showingAll ? "Show last scan only" : "Show all " + log.length + " scans"}
           </button>`
        : "");
  }

  renderItems();

  // One click handler covers both "see more" inside cards and "show all"
  listEl.onclick = (e) => {
    if (e.target.id === "showAllBtn") {
      showingAll = !showingAll;
      renderItems();
      return;
    }
    const btn = e.target.closest(".see-more-btn");
    if (!btn) return;
    const idx   = btn.dataset.idx;
    const total = btn.dataset.total;
    const extra = document.getElementById(`extra-${idx}`);
    if (!extra) return;
    const open = extra.style.display === "none";
    extra.style.display = open ? "block" : "none";
    btn.textContent = open ? "Show less" : `See ${total} more details`;
  };
}


// =============================================================================
// NORMALIZE STATE
// The old code stored state as "Safe", "High Risk", "unsafe", etc.
// This normalizes everything to a consistent internal key.
// =============================================================================
function normalizeState(entry) {
  if (!entry) return { score: 0, stateKey: "safe", reasons: [], source: "heuristic" };

  const score = entry.score || 0;
  const reasons = entry.reasons || [];
  const source = entry.source || "heuristic";

  // Normalize state string to safe/warning/unsafe
  const raw = (entry.state || "").toLowerCase();
  const stateKey =
    raw.includes("unsafe") || raw.includes("high")   ? "unsafe"  :
    raw.includes("warning") || raw.includes("medium") ? "warning" : "safe";

  return { score, stateKey, reasons, source };
}
