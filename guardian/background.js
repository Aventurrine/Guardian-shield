// =============================================================================
// Guardian Shield — background.js  (MV3 Service Worker)
// Responsible for:
//   1. Receiving heuristic scan results from content.js
//   2. Running VirusTotal + Google Safe Browsing API checks (Layer 2 & 3)
//   3. Combining scores and updating icon/badge
//   4. Logging results to activity log (popup reads this)
//   5. Sending "block" command back to content.js in enforcement mode
//   6. Answering popup's "getState" queries for current-page display
// =============================================================================

// ── ICONS ─────────────────────────────────────────────────────────────────────
const ICON_SAFE   = "icon_safe.png";
const ICON_UNSAFE = "icon_unsafe.png";

// ── API KEYS ──────────────────────────────────────────────────────────────────
// For academic/testing use only — do not redistribute.
const VIRUSTOTAL_KEY    = "52f456777b7735b212bc3e258982a0c4d36bcbdf9e345abb5114d434e2fda763";
const SAFE_BROWSING_KEY = "AIzaSyAjwObYHAo_XFmKB7DQbAI-ikWW9LP3vS8";

// ── STATE STORES ──────────────────────────────────────────────────────────────
// tabState: most recent analysis result per tab (popup reads via getState message)
const tabState = new Map();

// apiCache: avoid re-querying APIs for the same URL within 5 minutes
// MV3 service workers can restart at any time, so this is in-memory only.
const apiCache = new Map(); // url → { result, timestamp }
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// pendingChecks: prevents duplicate API calls when content.js sends twice for the same URL
const pendingChecks = new Set();

// withTimeout: hard deadline on any promise — APIs can't hang forever
// If the API doesn't respond in `ms` milliseconds, it's treated as a failure.
function withTimeout(promise, ms) {
  const timer = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("timeout")), ms)
  );
  return Promise.race([promise, timer]);
}


// =============================================================================
// MESSAGE HANDLER
// =============================================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── Popup requests current tab state ─────────────────────────────────────
  if (msg.type === "getState") {
    sendResponse({ state: tabState.get(msg.tabId) || null });
    return; // synchronous, no need to return true
  }

  // ── Content script sends initial heuristic scan ───────────────────────────
  if (msg.type === "scan") {
    const tabId = sender?.tab?.id;
    if (!tabId) return;

    // Step 1: Apply heuristic result immediately for instant visual feedback
    applyResult(tabId, {
      score:     msg.score,
      state:     msg.state,
      reasons:   msg.reasons,
      url:       msg.url,
      host:      msg.host,
      source:    "heuristic",
      apiStatus: "checking", // tells popup "API check in progress"
      time:      new Date().toLocaleTimeString()
    });

    // Step 2: Run API checks in the background (1-3 seconds)
    runAPIChecks(tabId, msg.url, msg.score, msg.reasons);

    sendResponse({ ok: true });
  }
});


// =============================================================================
// APPLY RESULT
// Updates icon, badge, tab state map, and activity log.
// Called twice per page: once with heuristic result, once after APIs return.
// =============================================================================
function applyResult(tabId, result) {
  tabState.set(tabId, result);
  updateIcon(tabId, result.state);
  updateBadge(tabId, result.score, result.state);

  const severity =
    result.score >= 50 ? "High"   :
    result.score >= 20 ? "Medium" : "Low";

  chrome.storage.local.get({ activityLog: [] }, ({ activityLog }) => {
    // Update existing entry for this URL instead of duplicating
    const idx = activityLog.findIndex(e => e.url === result.url);
    const entry = { ...result, severity };
    if (idx >= 0) {
      activityLog[idx] = entry;
    } else {
      activityLog.unshift(entry);
    }
    chrome.storage.local.set({ activityLog: activityLog.slice(0, 30) });
  });
}


// =============================================================================
// API CHECKS — Layer 2 (VirusTotal) + Layer 3 (Google Safe Browsing)
// Both run in parallel via Promise.allSettled so one failure doesn't block the other.
// =============================================================================
async function runAPIChecks(tabId, url, heuristicScore, heuristicReasons) {
  // Skip non-HTTP pages (chrome://, about:, extension pages, etc.)
  if (!url.startsWith("http")) return;

  // If another call for this URL is already in-flight, skip — avoids duplicate API hits
  // when content.js sends the scan message twice (initial + retry)
  if (pendingChecks.has(url)) return;

  // Check cache first — avoid re-querying APIs for the same URL within 5 minutes
  const cached = apiCache.get(url);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
    mergeFinalResult(tabId, url, heuristicScore, heuristicReasons, cached.result);
    return;
  }

  pendingChecks.add(url);

  try {
    // Run both APIs in parallel with a 4-second hard timeout each.
    // withTimeout ensures a slow or unreachable API never leaves the
    // popup stuck on "Checking..." forever.
    const [vtSettled, sbSettled] = await Promise.allSettled([
      withTimeout(checkVirusTotal(url),   15000),
      withTimeout(checkSafeBrowsing(url), 15000)
    ]);

    const apiResult = {
      vt: vtSettled.status === "fulfilled" ? vtSettled.value : { checked: false },
      sb: sbSettled.status === "fulfilled" ? sbSettled.value : { flagged: false }
    };

    // Cache so repeated visits don't re-query
    apiCache.set(url, { result: apiResult, timestamp: Date.now() });

    mergeFinalResult(tabId, url, heuristicScore, heuristicReasons, apiResult);

  } finally {
    // Always release the lock — even if something throws
    pendingChecks.delete(url);
  }
}


// =============================================================================
// MERGE FINAL RESULT
// Combines heuristic score with API findings to produce the final verdict.
// Scoring logic:
//   Google Safe Browsing hit → score jumps to at least 85 (definitive block list)
//   VirusTotal malicious engines → scales with count, max +75
//   VirusTotal suspicious only → at least 30
//   Heuristic scores remain as the base
// =============================================================================
function mergeFinalResult(tabId, url, heuristicScore, heuristicReasons, apiResult) {
  let finalScore   = heuristicScore;
  let finalReasons = [...heuristicReasons];
  let source       = "heuristic";

  const { vt, sb } = apiResult;

  // ── Google Safe Browsing ────────────────────────────────────────────────
  // This is a Google-maintained definitive blocklist. A hit here is serious.
  if (sb.flagged) {
    finalScore = Math.max(finalScore, 85);
    finalReasons.push(
      `🚨 Google Safe Browsing flagged this as: ${formatSBThreat(sb.threatType)}`
    );
    source = "safebrowsing";
  }

  // ── VirusTotal ─────────────────────────────────────────────────────────
  if (vt.checked && vt.total > 0) {
    const flagged  = vt.malicious + vt.suspicious;
    const percent  = Math.round((flagged / vt.total) * 100);

    if (vt.malicious > 0) {
      // Scale: each malicious engine adds ~4 points, capped at 75
      // E.g. 1 engine = 24, 5 engines = 40, 15+ engines = 75
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
      // Clean VT result
      finalReasons.push(`✅ VirusTotal: clean (0/${vt.total} engines flagged)`);
    }

    // Show reported content categories if anything was flagged
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

  // Update icon, badge, log with final result
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

  // ── Enforcement mode blocking ─────────────────────────────────────────
  // If the page is unsafe AND user has enforcement mode on,
  // tell content.js to inject the block overlay.
  if (state === "unsafe") {
    chrome.storage.sync.get({ mode: "guided" }, ({ mode }) => {
      if (mode === "enforcement") {
        chrome.tabs.sendMessage(tabId, {
          type:    "block",
          score:   finalScore,
          reasons: finalReasons,
          source
        }).catch(() => {}); // silently ignore if tab navigated away
      }
    });
  }
}


// =============================================================================
// VIRUSTOTAL API v3
// Checks a URL against 70+ antivirus engines.
// Uses the URL ID approach (base64url of the URL) for a direct GET —
// faster than submitting for a new scan and waiting for results.
// Rate limit: 4 requests/minute on free tier.
// =============================================================================
async function checkVirusTotal(url) {
  try {
    // VT URL ID = base64url(url) without = padding
    // encodeURIComponent first handles non-ASCII characters in URLs
    const urlId = btoa(encodeURIComponent(url).replace(/%([0-9A-F]{2})/g,
        (_, p1) => String.fromCharCode("0x" + p1)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    // AbortController lets us cancel the underlying TCP connection, not just the promise.
    // This is what actually stops the browser from waiting on a stalled request.
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 14000);

    const res = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { headers: { "x-apikey": VIRUSTOTAL_KEY }, signal: ctrl.signal }
    );
    clearTimeout(timer);

    // 404 = URL not in VT database (not inherently dangerous, just unknown)
    if (res.status === 404) {
      return { checked: true, malicious: 0, suspicious: 0, total: 0, categories: [] };
    }
    if (!res.ok) return { checked: false };

    const data = await res.json();
    const stats   = data?.data?.attributes?.last_analysis_stats   || {};
    const results = data?.data?.attributes?.last_analysis_results || {};
    const catObj  = data?.data?.attributes?.categories            || {};

    // Deduplicate category names (many engines report the same category)
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


// =============================================================================
// GOOGLE SAFE BROWSING API v4
// Checks URL against Google's threat lists:
//   MALWARE, SOCIAL_ENGINEERING (phishing), UNWANTED_SOFTWARE, PHA
// Returns immediately — no async polling needed.
// =============================================================================
async function checkSafeBrowsing(url) {
  try {
    const body = {
      client: { clientId: "guardian-shield-ext", clientVersion: "2.0" },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",        // phishing / impersonation
          "UNWANTED_SOFTWARE",          // adware / PUP
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


// =============================================================================
// HELPERS
// =============================================================================

// Human-readable Safe Browsing threat type names
function formatSBThreat(type) {
  const labels = {
    "MALWARE":                        "Malware",
    "SOCIAL_ENGINEERING":             "Phishing",
    "UNWANTED_SOFTWARE":              "Unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION":"Harmful application"
  };
  return labels[type] || type;
}

// Switch icon based on safety state
// "safe" → green icon  |  "warning" or "unsafe" → red icon
function updateIcon(tabId, state) {
  const icon = state === "safe" ? ICON_SAFE : ICON_UNSAFE;
  chrome.action.setIcon({
    tabId,
    path: { 16: icon, 32: icon, 48: icon, 128: icon }
  }).catch(() => {}); // tab may be gone
}

// Badge text + color
// safe  → no badge
// warning (20-49) → amber badge with score
// unsafe (50+)    → red badge with score
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


// =============================================================================
// TAB NAVIGATION — reset icon/badge when tab starts loading a new page
// =============================================================================
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    tabState.delete(tabId);
    updateIcon(tabId, "safe");
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }
});
