// =============================================================================
// Guardian Shield — content.js
// Runs on every page. Responsible for:
//   1. Layer 1: Instant URL heuristic analysis (no API, runs immediately)
//   2. Layer 2: DOM behavioral analysis (password fields, forms, iframes, etc.)
//   3. Sending combined results to background.js for API verification
//   4. Listening for "block" command from background and showing the overlay
// =============================================================================

// ── IFRAME WHITELIST ──────────────────────────────────────────────────────────
// Hidden iframes from these well-known hosts are ignored.
// Without this, every site using Google Tag Manager or ad networks would flag.
const TRUSTED_IFRAME_HOSTS = [
  // Google
  "google.com","googleapis.com","googletagmanager.com","googleadservices.com",
  "doubleclick.net","googlesyndication.com","gstatic.com","recaptcha.net","google-analytics.com",
  // Amazon / AWS
  "amazon.com","amazon.sa","amazon.co.uk","amazon.ae","amazon.de",
  "cloudfront.net","amazon-adsystem.com","awsstatic.com",
  // Streaming / social
  "twitch.tv","twitchsvc.net","jtvnw.net",
  "facebook.com","fbcdn.net","instagram.com","twitter.com","x.com",
  "youtube.com","ytimg.com","vimeo.com",
  // Payments
  "stripe.com","paypal.com","braintreegateway.com",
  // Analytics
  "hotjar.com","clarity.ms","segment.com","mixpanel.com",
  // CDN / infra
  "cloudflare.com","fastly.net","akamaized.net"
];

function isTrustedIframeHost(src) {
  try {
    const h = new URL(src).hostname;
    return TRUSTED_IFRAME_HOSTS.some(t => h === t || h.endsWith("." + t));
  } catch { return false; }
}


// =============================================================================
// ENFORCEMENT OVERLAY
// Shows a full-screen block when enforcement mode is on and a threat is found.
// The user can still click "Proceed anyway" — we can't hard-block in MV3.
// =============================================================================
function showBlockOverlay(score, reasons, source) {
  // Don't inject twice
  if (document.getElementById("__gs_overlay")) return;

  // Freeze page scroll so they can't just scroll past the warning
  document.documentElement.style.overflow = "hidden";

  const overlay = document.createElement("div");
  overlay.id = "__gs_overlay";
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:2147483647;
    background:rgba(4,6,15,0.98);
    display:flex;align-items:center;justify-content:center;
    font-family:system-ui,-apple-system,sans-serif;
    animation:__gs_fade 0.2s ease;
  `;

  // Human-readable label for which system caught it
  const sourceLabel = {
    safebrowsing: "Google Safe Browsing",
    virustotal:   "VirusTotal (70+ antivirus engines)",
    heuristic:    "Local Pattern Analysis"
  }[source] || "Guardian Shield";

  const riskColor = score >= 80 ? "#ef4444" : "#f59e0b";
  const reasonsHTML = reasons.map(r =>
    `<li style="margin:6px 0;color:#fca5a5;line-height:1.5;font-size:13px">${r}</li>`
  ).join("");

  overlay.innerHTML = `
    <style>
      @keyframes __gs_fade { from { opacity:0; transform:scale(0.97) } to { opacity:1; transform:scale(1) } }
    </style>
    <div style="
      max-width:480px;width:92%;
      background:#0f172a;
      border:1px solid rgba(239,68,68,0.45);
      border-radius:22px;padding:36px 32px;
      text-align:center;
      box-shadow:0 0 90px rgba(239,68,68,0.18), 0 24px 60px rgba(0,0,0,0.6);
    ">
      <div style="font-size:54px;margin-bottom:14px;filter:drop-shadow(0 0 12px #ef4444)">🛡️</div>

      <h2 style="margin:0 0 8px;color:${riskColor};font-size:23px;font-weight:800;letter-spacing:-0.02em">
        Dangerous Page Blocked
      </h2>

      <p style="margin:0 0 4px;color:#94a3b8;font-size:12px">
        Detected by: <strong style="color:#e2e8f0">${sourceLabel}</strong>
      </p>
      <p style="margin:0 0 22px;color:#475569;font-size:12px">
        Risk score: <strong style="color:${riskColor};font-size:15px">${score}</strong>
        <span style="color:#334155">/100</span>
      </p>

      <ul style="
        text-align:left;padding:0 0 0 18px;margin:0 0 26px;
        max-height:180px;overflow-y:auto;
      ">
        ${reasonsHTML}
      </ul>

      <div style="display:flex;gap:10px">
        <button id="__gs_back" style="
          flex:2;padding:14px;border:none;border-radius:13px;
          background:#ef4444;color:#fff;font-weight:700;
          cursor:pointer;font-size:14px;
          box-shadow:0 4px 16px rgba(239,68,68,0.35);
        ">← Go Back to Safety</button>
        <button id="__gs_proceed" style="
          flex:1;padding:14px;
          border:1px solid rgba(148,163,184,0.18);
          border-radius:13px;background:transparent;
          color:#475569;font-weight:600;cursor:pointer;font-size:12px;
        ">Proceed anyway</button>
      </div>

      <p style="margin:16px 0 0;color:#1e293b;font-size:11px">
        Guardian Shield · Enforcement Mode · Disable in extension popup to allow
      </p>
    </div>
  `;

  document.documentElement.appendChild(overlay);

  document.getElementById("__gs_back").onclick     = () => history.back();
  document.getElementById("__gs_proceed").onclick  = () => {
    overlay.remove();
    document.documentElement.style.overflow = "";
  };
}


// =============================================================================
// LAYER 1 — URL HEURISTICS
// Analyzes the URL structure itself — no page content needed.
// These signals are fast and reliable for catching phishing domain tricks.
// =============================================================================
function analyzeURL() {
  let score = 0;
  const reasons = [];
  const hostname = location.hostname.toLowerCase();

  // ── Raw IP address ────────────────────────────────────────────────────────
  // Legitimate sites always use domain names. IPs in URLs = red flag.
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 30;
    reasons.push("⚠️ URL uses a raw IP address instead of a domain name");
  }

  // ── Unencrypted HTTP ──────────────────────────────────────────────────────
  if (location.protocol === "http:") {
    score += 15;
    reasons.push("🔓 Page loaded over HTTP (no encryption)");
  }

  // ── Suspicious free/throwaway TLDs ────────────────────────────────────────
  // These TLDs are free or very cheap and massively overrepresented in phishing
  const badTLDs = [".xyz",".top",".tk",".gq",".ml",".cf",".ga",
                   ".pw",".cc",".icu",".work",".click",".biz",".info"];
  const tldHit = badTLDs.find(t => hostname.endsWith(t));
  if (tldHit) {
    score += 20;
    reasons.push(`⚠️ Suspicious domain extension: "${tldHit}"`);
  }

  // ── Excessive subdomain depth ─────────────────────────────────────────────
  // Real sites rarely have 5+ domain parts. Phishers use this to bury the real domain.
  // e.g. secure.login.verify.paypal.com.evil.xyz
  const parts = hostname.split(".");
  if (parts.length >= 5) {
    score += 20;
    reasons.push(`⚠️ Unusually deep subdomain (${parts.length} levels) - often used to hide the real domain`);
  }

  // ── Brand name impersonation in subdomain ────────────────────────────────
  // The subdomain is everything BEFORE the last two parts (domain + TLD).
  // e.g. "paypal" in "paypal.verify.evil.com" → subdomain = "paypal.verify"
  const subdomain = parts.slice(0, -2).join(".");
  const brands = [
    "paypal","amazon","google","microsoft","apple","facebook","netflix",
    "instagram","twitter","ebay","bank","secure","login","verify","signin",
    "account","update","wallet","crypto","binance","coinbase"
  ];
  const brandHit = brands.find(b => subdomain.includes(b));
  if (brandHit && subdomain.length > 0) {
    score += 25;
    reasons.push(`🎭 "${brandHit}" appears in subdomain but is not the real domain`);
  }

  // ── URL-encoded characters in hostname ────────────────────────────────────
  // Percent-encoding in the domain is used to visually disguise a URL
  if (/%[0-9a-f]{2}/i.test(hostname)) {
    score += 20;
    reasons.push("🔍 URL contains encoded characters that disguise the real address");
  }

  return { score, reasons };
}


// =============================================================================
// LAYER 2 -- DOM / PAGE BEHAVIOR ANALYSIS
// Kept lightweight -- no full page text reads, no style reflows on big element
// sets. Each check bails out early once it finds what it needs.
// =============================================================================
function analyzeDOM() {
  let score = 0;
  const reasons = [];
  const isHTTP = location.protocol === "http:";

  // Password field on HTTP
  // HTTPS login pages are normal. Only flag when there is no encryption.
  if (isHTTP && document.querySelector("input[type='password']")) {
    score += 25;
    reasons.push("\uD83D\uDD11 Password form on HTTP - your password would be sent unencrypted");
  }

  // Phishing language
  // Read only the first 5000 chars from the page.
  // Reading the full innerText on a big site forces a layout reflow which was
  // the main reason scanning was slow.
  const textSample = (document.body?.innerText || "").slice(0, 5000).toLowerCase();
  const phishingPhrases = [
    "verify your account","confirm your identity","unusual sign-in activity",
    "account has been suspended","update your payment method",
    "click here to verify","immediate action required",
    "your account will be closed","your account has been limited"
  ];
  const phraseHit = phishingPhrases.find(p => textSample.includes(p));
  if (phraseHit) {
    score += 20;
    reasons.push(`\uD83D\uDCE7 Phishing text found: "${phraseHit}"`);
  }

  // Cross-domain form submission
  // Cap at 20 forms -- big sites can have dozens and we only need one hit.
  const forms = Array.from(document.querySelectorAll("form")).slice(0, 20);
  for (const form of forms) {
    const action = (form.getAttribute("action") || "").trim();
    if (action.startsWith("http") && !action.includes(location.hostname)) {
      score += 30;
      reasons.push("\uD83D\uDCE4 Form on this page sends data to a different site");
      break;
    }
  }

  // Hidden iframes from unknown domains
  // Check HTML attributes only instead of calling getComputedStyle() per element.
  // getComputedStyle forces a style recalculation each call -- very slow on pages
  // with many iframes (ad-heavy sites, news sites, etc.).
  // Cap at 30 iframes.
  const iframes = Array.from(document.querySelectorAll("iframe")).slice(0, 30);
  let suspiciousCount = 0;
  for (const f of iframes) {
    const src = (f.getAttribute("src") || "").trim();
    if (!src || src === "about:blank" || src.startsWith("javascript:")) continue;
    if (isTrustedIframeHost(src)) continue;

    const styleAttr = (f.getAttribute("style") || "").toLowerCase();
    const w = parseInt(f.getAttribute("width")  || "99");
    const h = parseInt(f.getAttribute("height") || "99");
    const hidden =
      styleAttr.includes("display:none") ||
      styleAttr.includes("display: none") ||
      styleAttr.includes("visibility:hidden") ||
      styleAttr.includes("visibility: hidden") ||
      w < 5 || h < 5;

    if (hidden) suspiciousCount++;
  }
  if (suspiciousCount > 0) {
    score += 20;
    reasons.push(`\uD83D\uDDBD ${suspiciousCount} hidden iframe(s) loading from unknown sites`);
  }

  // Obfuscated scripts
  // Check first 10 inline scripts only, 2000 chars each.
  // Reading all inline scripts on a big page can mean several MB of JS.
  const inlineScripts = Array.from(document.querySelectorAll("script:not([src])"))
    .slice(0, 10)
    .map(s => (s.textContent || "").slice(0, 2000));

  const isRealObfuscation = (code) => {
    const lc = code.toLowerCase();
    // These two patterns have no legitimate use in modern code
    if (lc.includes("eval(unescape("))           return true;
    if (lc.includes("document.write(unescape(")) return true;
    // Hex blob check: only flag if there are 8+ hex escapes in a row with no gap.
    // Google uses scattered \x3c for HTML escaping -- that won't match this.
    // A real hex payload looks like \x65\x76\x61\x6c (no breaks).
    if (/(?:\\x[0-9a-fA-F]{2}){8,}/.test(code)) return true;
    return false;
  };
  if (inlineScripts.some(isRealObfuscation)) {
    score += 20;
    reasons.push("\uD83D\uDCBB Obfuscated script found - code is encoded to hide what it does");
  }

  return { score, reasons };
}


// =============================================================================
// MAIN — combines both layers and sends to background.js
// =============================================================================
function analyze() {
  const urlResult = analyzeURL();
  const domResult = analyzeDOM();

  const combinedScore   = Math.min(100, urlResult.score + domResult.score);
  const combinedReasons = [...urlResult.reasons, ...domResult.reasons];

  // State tiers: safe (0-19) | warning (20-49) | unsafe (50+)
  const state =
    combinedScore >= 50 ? "unsafe"  :
    combinedScore >= 20 ? "warning" : "safe";

  // Send to background.js which will:
  //   (a) Update icon/badge immediately with these heuristic results
  //   (b) Run VirusTotal + Google Safe Browsing API checks asynchronously
  //   (c) Send a "block" message back here if enforcement mode + threat confirmed
  // Single send only — background uses pendingChecks to deduplicate anyway,
  // but removing the duplicate retry here cuts API call frequency in half.
  chrome.runtime.sendMessage({
    type:    "scan",
    score:   combinedScore,
    state,
    reasons: combinedReasons,
    url:     location.href,
    host:    location.hostname,
    source:  "heuristic"
  }, () => void chrome.runtime.lastError);
}


// =============================================================================
// LISTENER — receives "block" from background after API checks confirm threat
// =============================================================================
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "block") {
    showBlockOverlay(msg.score, msg.reasons, msg.source);
  }
});


// Run once after page fully loads.
// Single trigger — avoids the double-run bug from using both
// window.load AND DOMContentLoaded.
setTimeout(analyze, 1000);
