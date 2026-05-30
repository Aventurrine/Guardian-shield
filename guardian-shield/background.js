// Guardian Shield — background.js

// Icons
const ICON_SAFE   = "icon_safe.png";
const ICON_UNSAFE = "icon_unsafe.png";

// API keys
const VIRUSTOTAL_KEY    = "PUT_YOUR_VIRUSTOTAL_KEY_HERE";
const SAFE_BROWSING_KEY = "PUT_YOUR_SAFE_BROWSING_KEY_HERE";

// State stores
const tabState     = new Map();
const apiCache     = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;
const pendingChecks = new Set();

// Timeout helper
function withTimeout(promise, ms) {
  const timer = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("timeout")), ms)
  );
  return Promise.race([promise, timer]);
}


// Message handler
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // Popup query
  if (msg.type === "getState") {
    sendResponse({ state: tabState.get(msg.tabId) || null });
    return;
  }

  // Heuristic scan
  if (msg.type === "scan") {
    const tabId = sender?.tab?.id;
    if (!tabId) return;

    // Apply immediately
    applyResult(tabId, {
      score:     msg.score,
      state:     msg.state,
      reasons:   msg.reasons,
      url:       msg.url,
      host:      msg.host,
      source:    "heuristic",
      apiStatus: "checking",
      time:      new Date().toLocaleTimeString()
    });

    // Run APIs
    runAPIChecks(tabId, msg.url, msg.score, msg.reasons);

    sendResponse({ ok: true });
  }
});


// Apply result
function applyResult(tabId, result) {
  tabState.set(tabId, result);
  updateIcon(tabId, result.state);
  updateBadge(tabId, result.score, result.state);

  const severity =
    result.score >= 50 ? "High"   :
    result.score >= 20 ? "Medium" : "Low";

  chrome.storage.local.get({ activityLog: [] }, ({ activityLog }) => {
    const idx   = activityLog.findIndex(e => e.url === result.url);
    const entry = { ...result, severity };
    if (idx >= 0) {
      activityLog[idx] = entry;
    } else {
      activityLog.unshift(entry);
    }
    chrome.storage.local.set({ activityLog: activityLog.slice(0, 30) });
  });
}


// Run API checks
async function runAPIChecks(tabId, url, heuristicScore, heuristicReasons) {
  if (!url.startsWith("http")) return;
  if (pendingChecks.has(url)) return;

  // Check cache
  const cached = apiCache.get(url);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
    mergeFinalResult(tabId, url, heuristicScore, heuristicReasons, cached.result);
    return;
  }

  pendingChecks.add(url);

  try {
    const [vtSettled, sbSettled] = await Promise.allSettled([
      withTimeout(checkVirusTotal(url),   15000),
      withTimeout(checkSafeBrowsing(url), 15000)
    ]);

    const apiResult = {
      vt: vtSettled.status === "fulfilled" ? vtSettled.value : { checked: false },
      sb: sbSettled.status === "fulfilled" ? sbSettled.value : { flagged: false }
    };

    apiCache.set(url, { result: apiResult, timestamp: Date.now() });
    mergeFinalResult(tabId, url, heuristicScore, heuristicReasons, apiResult);

  } finally {
    pendingChecks.delete(url);
  }
}


// Merge final result
function mergeFinalResult(tabId, url, heuristicScore, heuristicReasons, apiResult) {
  let finalScore   = heuristicScore;
  let finalReasons = [...heuristicReasons];
  let source       = "heuristic";

  const { vt, sb } = apiResult;

  // Safe Browsing
  if (sb.flagged) {
    finalScore = Math.max(finalScore, 85);
    finalReasons.push(
      `🚨 Google Safe Browsing flagged this as: ${formatSBThreat(sb.threatType)}`
    );
    source = "safebrowsing";
  }

  // VirusTotal
  if (vt.checked && vt.total > 0) {
    const flagged = vt.malicious + vt.suspicious;
    const percent = Math.round((flagged / vt.total) * 100);

    if (vt.malicious > 0) {
      const vtScore = Math.min(75, 20 + vt.malicious * 4);
      finalScore = Math.max(finalScore, vtScore);
      finalReasons.push(
        `🦠 VirusTotal: ${vt.malicious}/${vt.total} engines flagged this URL (${percent}% detection rate)`
      );
      if (source === "heuristic") source = "virustotal";
    } else if (vt.suspicious > 0) {
      finalScore = Math.max(finalScore, 30);
      finalReasons.push(
        `⚠️ VirusTotal: ${vt.suspicious}/${vt.total} engines marked this URL as suspicious`
      );
    } else {
      finalReasons.push(`✅ VirusTotal: clean (0/${vt.total} engines flagged)`);
    }

    if (vt.categories.length > 0 && flagged > 0) {
      finalReasons.push(`📋 Category: ${vt.categories.slice(0, 3).join(", ")}`);
    }
  } else if (!vt.checked) {
    finalReasons.push("⚪ VirusTotal: could not connect");
  }

  finalScore = Math.min(100, Math.max(0, finalScore));
  const state =
    finalScore >= 50 ? "unsafe"  :
    finalScore >= 20 ? "warning" : "safe";

  let host = "";
  try { host = new URL(url).hostname; } catch {}

  applyResult(tabId, {
    score:     finalScore,
    state,
    reasons:   finalReasons,
    url,
    host,
    source,
    apiStatus: "done",
    time:      new Date().toLocaleTimeString()
  });

  // Enforcement blocking
  if (state === "unsafe") {
    chrome.storage.sync.get({ mode: "guided" }, ({ mode }) => {
      if (mode === "enforcement") {
        chrome.tabs.sendMessage(tabId, {
          type:    "block",
          score:   finalScore,
          reasons: finalReasons,
          source
        }).catch(() => {});
      }
    });
  }
}


// VirusTotal API
async function checkVirusTotal(url) {
  try {
    const urlId = btoa(encodeURIComponent(url).replace(/%([0-9A-F]{2})/g,
        (_, p1) => String.fromCharCode("0x" + p1)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 14000);

    const res = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { headers: { "x-apikey": VIRUSTOTAL_KEY }, signal: ctrl.signal }
    );
    clearTimeout(timer);

    if (res.status === 404) {
      return { checked: true, malicious: 0, suspicious: 0, total: 0, categories: [] };
    }
    if (!res.ok) return { checked: false };

    const data       = await res.json();
    const stats      = data?.data?.attributes?.last_analysis_stats   || {};
    const results    = data?.data?.attributes?.last_analysis_results || {};
    const catObj     = data?.data?.attributes?.categories            || {};
    const categories = [...new Set(Object.values(catObj).filter(Boolean))];

    return {
      checked:    true,
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      total:      Object.keys(results).length,
      categories
    };
  } catch (e) {
    return { checked: false };
  }
}


// Safe Browsing API
async function checkSafeBrowsing(url) {
  try {
    const body = {
      client: { clientId: "guardian-shield-ext", clientVersion: "2.0" },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes:    ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries:    [{ url }]
      }
    };

    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`,
      {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body)
      }
    );

    if (!res.ok) return { flagged: false };

    const data = await res.json();
    if (data.matches?.length > 0) {
      return {
        flagged:      true,
        threatType:   data.matches[0].threatType,
        platformType: data.matches[0].platformType
      };
    }
    return { flagged: false };
  } catch (e) {
    return { flagged: false };
  }
}


// Helpers
function formatSBThreat(type) {
  const labels = {
    "MALWARE":                         "Malware",
    "SOCIAL_ENGINEERING":              "Phishing",
    "UNWANTED_SOFTWARE":               "Unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Harmful application"
  };
  return labels[type] || type;
}

function updateIcon(tabId, state) {
  const icon = state === "safe" ? ICON_SAFE : ICON_UNSAFE;
  chrome.action.setIcon({
    tabId,
    path: { 16: icon, 32: icon, 48: icon, 128: icon }
  }).catch(() => {});
}

function updateBadge(tabId, score, state) {
  if (state === "safe" || score === 0) {
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
    return;
  }
  const text  = String(Math.min(99, score));
  const color = state === "unsafe" ? "#ef4444" : "#f59e0b";
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}


// Tab navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    tabState.delete(tabId);
    updateIcon(tabId, "safe");
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }
});
