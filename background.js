// background.js — the MV3 service worker.
//
// This file has no access to any page's DOM. It only reacts to browser-level
// events (navigation, tab switching, network errors) and controls the
// toolbar action (icon/badge). Because MV3 service workers can be killed by
// Chrome whenever they're idle (as soon as ~30s after their last event) and
// woken back up on the next event, module-level variables don't reliably
// survive "for a while" — a killed-and-restarted worker starts fresh.
//
// For certErrorByTab/safeBrowsingByTab that matters: they hold active
// security warnings, and silently losing one mid-session (e.g. you switch
// away from a flagged tab, the worker naps, you switch back — badge now
// wrongly looks clean) would undermine the one thing this extension is for.
// So these two are mirrored into chrome.storage.session, which persists
// across worker restarts and is only cleared when Chrome fully quits — the
// Maps stay the synchronous source of truth for badge computation, storage
// is just the durability layer underneath. Every reader and writer awaits
// the `stateReady` promise below first, so a worker that just woke up can
// never act on an empty Map before rehydration has actually landed.

// tabId -> { hadCertError: boolean }
const certErrorByTab = new Map();

// tabId -> { checked: boolean, malicious: boolean, threatTypes: string[] }
const safeBrowsingByTab = new Map();

function persistTabMap(storageKey, map) {
  chrome.storage.session.set({ [storageKey]: Object.fromEntries(map) });
}

async function rehydrateTabMap(storageKey, map) {
  const result = await chrome.storage.session.get(storageKey);
  for (const [tabId, value] of Object.entries(result[storageKey] || {})) {
    map.set(Number(tabId), value);
  }
}

// chrome.storage.session.get is genuinely async — without this gate, a
// listener firing right after a worker wake (the exact "switch back to a
// flagged tab" case this whole mechanism exists for) could still read the
// Maps before rehydration lands, and briefly show a falsely-clean result.
// Every function that reads OR writes either Map awaits this first — write
// sites need it too, so a late-arriving rehydration can never clobber a
// fresher live update by re-applying stale stored data on top of it.
const stateReady = Promise.all([
  rehydrateTabMap("certErrorByTab", certErrorByTab),
  rehydrateTabMap("safeBrowsingByTab", safeBrowsingByTab),
]);

// In-memory cache of Safe Browsing results by exact URL, so revisiting the
// same URL in this browser session (e.g. switching between two tabs on the
// same site) doesn't spend another API call. Cleared when the worker
// restarts — unlike the two Maps above, that's fine here: losing this cache
// only costs an extra API call, never a wrong or missing security signal.
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

async function setBadgeForTab(tabId, url) {
  if (!isTrackedProtocol(url)) {
    // chrome://, file://, extension pages, new-tab page, etc. — nothing
    // meaningful to say about "connection security" here, so clear the badge.
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  await stateReady;
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
  await stateReady;

  if (safeBrowsingCacheByUrl.has(url)) {
    safeBrowsingByTab.set(tabId, safeBrowsingCacheByUrl.get(url));
    persistTabMap("safeBrowsingByTab", safeBrowsingByTab);
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
  persistTabMap("safeBrowsingByTab", safeBrowsingByTab);
  setBadgeForTab(tabId, url);
}

// When the worker starts up (browser launch, or the extension being
// installed/updated/reloaded) there's no per-tab state yet, but tabs may
// already be sitting open from before. Without this, their badge stays
// blank and their Safe Browsing check never runs until the user reloads —
// checkSafeBrowsing() is otherwise only triggered by onUpdated's "complete".
function initializeAllTabs() {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (!isTrackedProtocol(tab.url)) continue;
      setBadgeForTab(tab.id, tab.url);
      checkSafeBrowsing(tab.id, tab.url);
    }
  });
}
chrome.runtime.onInstalled.addListener(initializeAllTabs);
chrome.runtime.onStartup.addListener(initializeAllTabs);

// Fires whenever a tab's URL, loading state, etc. changes. We care about two
// moments: navigation starting (reset stale per-page state) and the page
// finishing load (recompute the badge with fresh info).
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    // New navigation on this tab — old cert-error / Safe Browsing data no
    // longer applies. (Link-scan results aren't cached here; the popup
    // pulls those fresh from content.js on demand.)
    await stateReady;
    certErrorByTab.delete(tabId);
    safeBrowsingByTab.delete(tabId);
    persistTabMap("certErrorByTab", certErrorByTab);
    persistTabMap("safeBrowsingByTab", safeBrowsingByTab);
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

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await stateReady;
  certErrorByTab.delete(tabId);
  safeBrowsingByTab.delete(tabId);
  persistTabMap("certErrorByTab", certErrorByTab);
  persistTabMap("safeBrowsingByTab", safeBrowsingByTab);
});

// webRequest lets us observe network-level events without modifying traffic
// (we didn't request "webRequestBlocking", so this is read-only/observational).
// When the main page navigation itself fails with a certificate-related
// error, Chrome shows its own red interstitial warning page — we want our
// badge to agree with that rather than falling back to a stale "secure" state.
chrome.webRequest.onErrorOccurred.addListener(
  async (details) => {
    if (details.type !== "main_frame") return;
    if (!/CERT/i.test(details.error)) return;
    await stateReady;
    certErrorByTab.set(details.tabId, { hadCertError: true });
    persistTabMap("certErrorByTab", certErrorByTab);
    setBadgeForTab(details.tabId, details.url);
  },
  { urls: ["<all_urls>"] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_TAB_STATUS") {
    const tabId = message.tabId;
    stateReady.then(() => {
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab) {
          sendResponse({ ok: false });
          return;
        }
        const isHttps = typeof tab.url === "string" && tab.url.startsWith("https://");
        const isHttp = typeof tab.url === "string" && tab.url.startsWith("http://");

        // Pull fresh link-scan results straight from content.js rather than
        // trusting anything cached here — see the comment on the matching
        // listener in content.js for why. This fails (lastError set, no
        // response) on tabs with no content script, e.g. chrome:// pages.
        chrome.tabs.sendMessage(tabId, { type: "GET_LINK_SCAN" }, (linksResponse) => {
          const links = chrome.runtime.lastError || !linksResponse ? { count: 0, items: [] } : linksResponse;
          sendResponse({
            ok: true,
            url: tab.url,
            security: {
              tracked: isHttps || isHttp,
              isHttps,
              hadCertError: certErrorByTab.get(tabId)?.hadCertError === true,
            },
            links,
            safeBrowsing: {
              enabled: cachedApiKey !== null,
              ...(safeBrowsingByTab.get(tabId) || { checked: false, malicious: false, threatTypes: [] }),
            },
          });
        });
      });
    });
    return true; // keep the message channel open for the async sendResponse
  }
});
