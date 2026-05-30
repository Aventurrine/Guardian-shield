// Guardian Shield — content.js

// Trusted iframe hosts
const TRUSTED_IFRAME_HOSTS = [
  "google.com","googleapis.com","googletagmanager.com","googleadservices.com",
  "doubleclick.net","googlesyndication.com","gstatic.com","recaptcha.net","google-analytics.com",
  "amazon.com","amazon.sa","amazon.co.uk","amazon.ae","amazon.de",
  "cloudfront.net","amazon-adsystem.com","awsstatic.com",
  "twitch.tv","twitchsvc.net","jtvnw.net",
  "facebook.com","fbcdn.net","instagram.com","twitter.com","x.com",
  "youtube.com","ytimg.com","vimeo.com",
  "stripe.com","paypal.com","braintreegateway.com",
  "hotjar.com","clarity.ms","segment.com","mixpanel.com",
  "cloudflare.com","fastly.net","akamaized.net"
];

function isTrustedIframeHost(src) {
  try {
    const h = new URL(src).hostname;
    return TRUSTED_IFRAME_HOSTS.some(t => h === t || h.endsWith("." + t));
  } catch { return false; }
}


// Block overlay
function showBlockOverlay(score, reasons, source) {
  if (document.getElementById("__gs_overlay")) return;

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

  const sourceLabel = {
    safebrowsing: "Google Safe Browsing",
    virustotal:   "VirusTotal (70+ antivirus engines)",
    heuristic:    "Local Pattern Analysis"
  }[source] || "Guardian Shield";

  const riskColor  = score >= 80 ? "#ef4444" : "#f59e0b";
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
      <ul style="text-align:left;padding:0 0 0 18px;margin:0 0 26px;max-height:180px;overflow-y:auto;">
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
  document.getElementById("__gs_back").onclick    = () => history.back();
  document.getElementById("__gs_proceed").onclick = () => {
    overlay.remove();
    document.documentElement.style.overflow = "";
  };
}


// URL heuristics
function analyzeURL() {
  let score = 0;
  const reasons = [];
  const hostname = location.hostname.toLowerCase();

  // Raw IP
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 30;
    reasons.push("⚠️ URL uses a raw IP address instead of a domain name");
  }

  // No HTTPS
  if (location.protocol === "http:") {
    score += 15;
    reasons.push("🔓 Page loaded over HTTP (no encryption)");
  }

  // Bad TLD
  const badTLDs = [".xyz",".top",".tk",".gq",".ml",".cf",".ga",
                   ".pw",".cc",".icu",".work",".click",".biz",".info"];
  const tldHit = badTLDs.find(t => hostname.endsWith(t));
  if (tldHit) {
    score += 20;
    reasons.push(`⚠️ Suspicious domain extension: "${tldHit}"`);
  }

  // Deep subdomain
  const parts = hostname.split(".");
  if (parts.length >= 5) {
    score += 20;
    reasons.push(`⚠️ Unusually deep subdomain (${parts.length} levels) - often used to hide the real domain`);
  }

  // Brand impersonation
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

  // Encoded hostname
  if (/%[0-9a-f]{2}/i.test(hostname)) {
    score += 20;
    reasons.push("🔍 URL contains encoded characters that disguise the real address");
  }

  return { score, reasons };
}


// DOM analysis
function analyzeDOM() {
  let score = 0;
  const reasons = [];
  const isHTTP = location.protocol === "http:";

  // Password on HTTP
  if (isHTTP && document.querySelector("input[type='password']")) {
    score += 25;
    reasons.push("🔑 Password form on HTTP - your password would be sent unencrypted");
  }

  // Phishing phrases
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
    reasons.push(`📧 Phishing text found: "${phraseHit}"`);
  }

  // Cross-domain form
  const forms = Array.from(document.querySelectorAll("form")).slice(0, 20);
  for (const form of forms) {
    const action = (form.getAttribute("action") || "").trim();
    if (action.startsWith("http") && !action.includes(location.hostname)) {
      score += 30;
      reasons.push("📤 Form on this page sends data to a different site");
      break;
    }
  }

  // Hidden iframes
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
    reasons.push(`🖥 ${suspiciousCount} hidden iframe(s) loading from unknown sites`);
  }

  // Obfuscated scripts
  const inlineScripts = Array.from(document.querySelectorAll("script:not([src])"))
    .slice(0, 10)
    .map(s => (s.textContent || "").slice(0, 2000));

  const isRealObfuscation = (code) => {
    const lc = code.toLowerCase();
    if (lc.includes("eval(unescape("))           return true;
    if (lc.includes("document.write(unescape(")) return true;
    if (/(?:\\x[0-9a-fA-F]{2}){8,}/.test(code)) return true;
    return false;
  };
  if (inlineScripts.some(isRealObfuscation)) {
    score += 20;
    reasons.push("💻 Obfuscated script found - code is encoded to hide what it does");
  }

  return { score, reasons };
}


// Main analysis
function analyze() {
  const urlResult = analyzeURL();
  const domResult = analyzeDOM();

  const combinedScore   = Math.min(100, urlResult.score + domResult.score);
  const combinedReasons = [...urlResult.reasons, ...domResult.reasons];

  const state =
    combinedScore >= 50 ? "unsafe"  :
    combinedScore >= 20 ? "warning" : "safe";

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


// Block listener
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "block") {
    showBlockOverlay(msg.score, msg.reasons, msg.source);
  }
});


// Run on load
setTimeout(analyze, 1000);
