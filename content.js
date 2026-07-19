// content.js — runs inside the actual web page (an "isolated world": it can
// read and modify the page's DOM, but the page's own scripts can't see or
// call anything defined here, and vice versa). This is the only piece of the
// extension that can see rendered <a> tags, so all link analysis happens here.

// A small hardcoded list of commonly-spoofed brand domains for the MVP
// typosquat check. Each entry is the real, canonical registrable domain.
const KNOWN_BRAND_DOMAINS = [
  "paypal.com",
  "amazon.com",
  "google.com",
  "microsoft.com",
  "apple.com",
  "facebook.com",
  "chase.com",
  "bankofamerica.com",
  "wellsfargo.com",
  "netflix.com",
  "instagram.com",
  "coinbase.com",
  "dropbox.com",
  "linkedin.com",
];

// Extract the "registrable" domain (roughly: last two labels) from a hostname,
// e.g. "www.mail.google.com" -> "google.com". This is a simplification (it
// doesn't know about multi-part public suffixes like "co.uk"), which is fine
// for comparing against our hardcoded ".com"-style brand list in the MVP.
function registrableDomain(hostname) {
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 2) return hostname.toLowerCase();
  return parts.slice(-2).join(".");
}

// Classic edit-distance (Levenshtein) between two strings.
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

// Is `hostname` a lookalike of one of our known brand domains? Returns the
// brand domain it resembles, or null. A hostname that legitimately IS the
// brand domain (or a subdomain of it, e.g. "checkout.paypal.com") is not
// flagged — only close-but-wrong spellings are.
function findTyposquatMatch(hostname) {
  const reg = registrableDomain(hostname);
  for (const brand of KNOWN_BRAND_DOMAINS) {
    if (reg === brand) return null; // legitimate, exact registrable domain
    const distance = levenshtein(reg, brand);
    // Small edit distance relative to the brand name's length = "close
    // misspelling" (e.g. "paypa1.com" vs "paypal.com" is distance 1).
    // Require some minimum length so we don't flag short, unrelated domains.
    if (brand.length >= 6 && distance > 0 && distance <= 2) {
      return brand;
    }
  }
  return null;
}

// Does the link's visible text look like it's claiming to be a URL/domain
// (e.g. text says "www.paypal.com" or "https://amazon.com/orders") that
// doesn't match where the link actually goes?
const URLISH_TEXT_RE = /(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/\S*)?/i;

function findTextMismatch(anchor, actualHostname) {
  const text = anchor.textContent.trim();
  const match = text.match(URLISH_TEXT_RE);
  if (!match) return null;

  // Only treat this as "the link text is claiming to be a URL" if the match
  // accounts for essentially the whole visible text, not an incidental
  // dotted word inside a longer sentence (e.g. "Node.js" in a paragraph).
  // Real spoofed links show the *entire* link text as a URL.
  const strippedText = text.replace(/[.,;:!?)]+$/, "");
  if (match[0] !== strippedText) return null;

  let claimedHostname;
  try {
    const claimedUrl = match[0].startsWith("http") ? match[0] : `http://${match[0]}`;
    claimedHostname = new URL(claimedUrl).hostname.toLowerCase();
  } catch {
    return null;
  }

  const claimedReg = registrableDomain(claimedHostname);
  const actualReg = registrableDomain(actualHostname);
  if (claimedReg !== actualReg) {
    return claimedHostname;
  }
  return null;
}

function analyzeAnchor(anchor) {
  let url;
  try {
    url = new URL(anchor.href);
  } catch {
    return null; // not a parseable absolute URL (e.g. javascript:, mailto: with no address)
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;

  const reasons = [];

  if (url.protocol === "http:") {
    reasons.push("Uses HTTP, not HTTPS (connection is not encrypted)");
  }

  const textMismatch = findTextMismatch(anchor, url.hostname);
  if (textMismatch) {
    reasons.push(`Link text says "${textMismatch}" but actually goes to "${url.hostname}"`);
  }

  const typosquat = findTyposquatMatch(url.hostname);
  if (typosquat) {
    reasons.push(`"${url.hostname}" looks like a misspelling of "${typosquat}"`);
  }

  if (reasons.length === 0) return null;
  return { href: url.href, reasons };
}

function flagAnchor(anchor, reasons) {
  anchor.style.outline = "2px solid #cf222e";
  anchor.style.backgroundColor = "rgba(207, 34, 46, 0.08)";
  const existingTitle = anchor.title ? `${anchor.title} — ` : "";
  anchor.title = `${existingTitle}⚠ Link Safety Checker: ${reasons.join("; ")}`;
}

function scanPage() {
  const anchors = document.querySelectorAll("a[href]");
  const items = [];

  for (const anchor of anchors) {
    const result = analyzeAnchor(anchor);
    if (result) {
      flagAnchor(anchor, result.reasons);
      items.push(result);
    }
  }

  chrome.runtime.sendMessage({
    type: "LINK_SCAN_RESULT",
    count: items.length,
    items: items.slice(0, 50), // cap payload size for pages with huge numbers of flags
  });
}

// MVP limitation: this scans once after the initial page render. Pages that
// inject links dynamically later (infinite-scroll feeds, SPA route changes)
// won't get re-scanned. A MutationObserver could cover that but adds
// complexity/perf cost we don't need for a first working version.
scanPage();
