// background.js — the MV3 service worker.
//
// This file has no access to any page's DOM. It only reacts to browser-level
// events (navigation, tab switching, network errors) and controls the
// toolbar action (icon/badge). Because MV3 service workers can be killed by
// Chrome whenever they're idle and woken back up on the next event, we can't
// assume module-level variables survive between events "for a while" — they
// survive fine *while the worker is alive*, but a killed-and-restarted
// worker starts these Maps empty again. That's acceptable here: state is
// naturally rebuilt as tabs re-navigate or the content script rescans.

// tabId -> { hadCertError: boolean }
const certErrorByTab = new Map();

// tabId -> { count: number, items: Array<{href: string, reasons: string[]}> }
const linkScanByTab = new Map();

// tabId -> { checked: boolean, malicious: boolean, threatTypes: string[] }
const safeBrowsingByTab = new Map();

// In-memory cache of Safe Browsing results by exact URL, so revisiting the
// same URL in this browser session (e.g. switching between two tabs on the
// same site) doesn't spend another API call. Cleared when the worker restarts.
const safeBrowsingCacheByUrl = new Map();

// Kept in sync with chrome.storage so we don't have to await a storage read
// on every navigation. Populated at startup and whenever options.js saves.
let cachedApiKey = null;
chrome.storage.local.get(["safeBrowsingApiKey"], (result) => {
  cachedApiKey = result.safeBrowsingApiKey || null;
});
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && "safeBrowsingApiKey" in changes) {
    cachedApiKey = changes.safeBrowsingApiKey.newValue || null;
  }
});

function isTrackedProtocol(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
}

function setBadgeForTab(tabId, url) {
  if (!isTrackedProtocol(url)) {
    // chrome://, file://, extension pages, new-tab page, etc. — nothing
    // meaningful to say about "connection security" here, so clear the badge.
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  const isHttps = url.startsWith("https://");
  const hadCertError = certErrorByTab.get(tabId)?.hadCertError === true;
  const safeBrowsing = safeBrowsingByTab.get(tabId);
  const isMalicious = safeBrowsing?.malicious === true;

  // Precedence: a Safe Browsing match is the most severe signal (a known-bad
  // site), then a certificate error, then plain HTTP, then "all clear".
  if (isMalicious) {
    chrome.action.setBadgeText({ tabId, text: "☠" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#57606a" }); // dark gray/black
    chrome.action.setTitle({
      tabId,
      title: `Google Safe Browsing flagged this site: ${safeBrowsing.threatTypes.join(", ")}`,
    });
  } else if (isHttps && !hadCertError) {
    chrome.action.setBadgeText({ tabId, text: "✓" }); // check mark
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#1a7f37" }); // green
    chrome.action.setTitle({ tabId, title: "Connection is HTTPS (certificate accepted by Chrome)" });
  } else if (isHttps && hadCertError) {
    chrome.action.setBadgeText({ tabId, text: "✕" }); // x mark
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#cf222e" }); // red
    chrome.action.setTitle({ tabId, title: "HTTPS, but Chrome reported a certificate error for this page" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#d4a72c" }); // yellow
    chrome.action.setTitle({ tabId, title: "Insecure connection (plain HTTP, not encrypted)" });
  }
}

const SAFE_BROWSING_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"];

// Calls the Safe Browsing Lookup API for a single URL and updates state/badge
// with the result. Silently does nothing if no API key has been configured
// yet in the options page.
async function checkSafeBrowsing(tabId, url) {
  if (!cachedApiKey) return;

  if (safeBrowsingCacheByUrl.has(url)) {
    safeBrowsingByTab.set(tabId, safeBrowsingCacheByUrl.get(url));
    setBadgeForTab(tabId, url);
    return;
  }

  let result;
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${cachedApiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "link-safety-checker", clientVersion: "0.1.0" },
        threatInfo: {
          threatTypes: SAFE_BROWSING_THREAT_TYPES,
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });
    if (!response.ok) return; // e.g. invalid key, quota exceeded — fail quietly
    const data = await response.json();
    const matches = data.matches || [];
    result = {
      checked: true,
      malicious: matches.length > 0,
      threatTypes: [...new Set(matches.map((m) => m.threatType))],
    };
  } catch {
    return; // network error — leave state as "not checked" rather than guessing
  }

  safeBrowsingCacheByUrl.set(url, result);
  safeBrowsingByTab.set(tabId, result);
  setBadgeForTab(tabId, url);
}

// Fires whenever a tab's URL, loading state, etc. changes. We care about two
// moments: navigation starting (reset stale per-page state) and the page
// finishing load (recompute the badge with fresh info).
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    // New navigation on this tab — old cert-error / link-scan / Safe
    // Browsing data no longer applies.
    certErrorByTab.delete(tabId);
    linkScanByTab.delete(tabId);
    safeBrowsingByTab.delete(tabId);
  }
  if (changeInfo.status === "complete" || changeInfo.url) {
    setBadgeForTab(tabId, tab.url);
  }
  if (changeInfo.status === "complete" && isTrackedProtocol(tab.url)) {
    checkSafeBrowsing(tabId, tab.url);
  }
});

// Fires when the user switches to a different tab — recompute so the badge
// reflects whichever tab is now active.
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) return;
    setBadgeForTab(tabId, tab.url);
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  certErrorByTab.delete(tabId);
  linkScanByTab.delete(tabId);
  safeBrowsingByTab.delete(tabId);
});

// webRequest lets us observe network-level events without modifying traffic
// (we didn't request "webRequestBlocking", so this is read-only/observational).
// When the main page navigation itself fails with a certificate-related
// error, Chrome shows its own red interstitial warning page — we want our
// badge to agree with that rather than falling back to a stale "secure" state.
chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    if (!/CERT/i.test(details.error)) return;
    certErrorByTab.set(details.tabId, { hadCertError: true });
    setBadgeForTab(details.tabId, details.url);
  },
  { urls: ["<all_urls>"] }
);

// Messages from content.js: results of scanning the page's links.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "LINK_SCAN_RESULT" && sender.tab) {
    linkScanByTab.set(sender.tab.id, {
      count: message.count,
      items: message.items,
    });
    return; // no response needed
  }

  if (message.type === "GET_TAB_STATUS") {
    const tabId = message.tabId;
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) {
        sendResponse({ ok: false });
        return;
      }
      const isHttps = typeof tab.url === "string" && tab.url.startsWith("https://");
      const isHttp = typeof tab.url === "string" && tab.url.startsWith("http://");
      sendResponse({
        ok: true,
        url: tab.url,
        security: {
          tracked: isHttps || isHttp,
          isHttps,
          hadCertError: certErrorByTab.get(tabId)?.hadCertError === true,
        },
        links: linkScanByTab.get(tabId) || { count: 0, items: [] },
        safeBrowsing: {
          enabled: cachedApiKey !== null,
          ...(safeBrowsingByTab.get(tabId) || { checked: false, malicious: false, threatTypes: [] }),
        },
      });
    });
    return true; // keep the message channel open for the async sendResponse
  }
});
