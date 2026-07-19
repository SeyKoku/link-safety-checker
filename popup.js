// popup.js — runs in the popup's own tiny document when the toolbar icon is
// clicked. It has no direct access to the page or the background worker's
// variables; it talks to background.js the same way content.js does, over
// chrome.runtime.sendMessage. The popup closes and is fully torn down every
// time it loses focus, so nothing here persists between openings — it just
// asks background.js for the latest known state each time it opens.

const badgeEl = document.getElementById("security-badge");
const detailEl = document.getElementById("security-detail");
const safeBrowsingBadgeEl = document.getElementById("safe-browsing-badge");
const safeBrowsingDetailEl = document.getElementById("safe-browsing-detail");
const linksHeadingEl = document.getElementById("links-heading");
const linksListEl = document.getElementById("links-list");

function renderSecurity(url, security) {
  if (!security.tracked) {
    badgeEl.className = "badge badge--unknown";
    badgeEl.textContent = "Not applicable";
    detailEl.textContent = "This isn't a regular http/https page.";
    return;
  }

  if (security.isHttps && !security.hadCertError) {
    badgeEl.className = "badge badge--secure";
    badgeEl.textContent = "✓ Secure (HTTPS)";
    detailEl.textContent = "Chrome validated this site's certificate.";
  } else if (security.isHttps && security.hadCertError) {
    badgeEl.className = "badge badge--insecure";
    badgeEl.textContent = "✕ Certificate problem";
    detailEl.textContent = "Chrome reported a certificate error for this page.";
  } else {
    badgeEl.className = "badge badge--warning";
    badgeEl.textContent = "! Not secure (HTTP)";
    detailEl.textContent = "This connection is not encrypted.";
  }
}

function renderSafeBrowsing(safeBrowsing) {
  if (!safeBrowsing.enabled) {
    safeBrowsingBadgeEl.className = "badge badge--unknown";
    safeBrowsingBadgeEl.textContent = "Not configured";
    safeBrowsingDetailEl.innerHTML = "";
    const link = document.createElement("a");
    link.href = "#";
    link.textContent = "Add a free Safe Browsing API key";
    link.addEventListener("click", (e) => {
      e.preventDefault();
      chrome.runtime.openOptionsPage();
    });
    safeBrowsingDetailEl.appendChild(link);
    return;
  }

  if (!safeBrowsing.checked) {
    safeBrowsingBadgeEl.className = "badge badge--unknown";
    safeBrowsingBadgeEl.textContent = "Checking…";
    safeBrowsingDetailEl.textContent = "Waiting on Google Safe Browsing.";
    return;
  }

  if (safeBrowsing.malicious) {
    safeBrowsingBadgeEl.className = "badge badge--insecure";
    safeBrowsingBadgeEl.textContent = "☠ Flagged by Safe Browsing";
    safeBrowsingDetailEl.textContent = safeBrowsing.threatTypes.join(", ");
  } else {
    safeBrowsingBadgeEl.className = "badge badge--secure";
    safeBrowsingBadgeEl.textContent = "✓ Not on Safe Browsing's list";
    safeBrowsingDetailEl.textContent = "";
  }
}

function renderLinks(links) {
  linksHeadingEl.textContent = `Suspicious links (${links.count})`;
  linksListEl.innerHTML = "";

  if (links.count === 0) {
    const li = document.createElement("li");
    li.className = "empty-state";
    li.textContent = "No suspicious links found on this page.";
    linksListEl.appendChild(li);
    return;
  }

  for (const item of links.items) {
    const li = document.createElement("li");

    const hrefEl = document.createElement("span");
    hrefEl.className = "link-href";
    hrefEl.textContent = item.href;

    const reasonsEl = document.createElement("span");
    reasonsEl.className = "link-reasons";
    reasonsEl.textContent = item.reasons.join("; ");

    li.appendChild(hrefEl);
    li.appendChild(reasonsEl);
    linksListEl.appendChild(li);
  }
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab) return;

  chrome.runtime.sendMessage({ type: "GET_TAB_STATUS", tabId: tab.id }, (response) => {
    if (!response || !response.ok) {
      badgeEl.className = "badge badge--unknown";
      badgeEl.textContent = "Unavailable";
      detailEl.textContent = "Could not read status for this tab.";
      return;
    }
    renderSecurity(response.url, response.security);
    renderSafeBrowsing(response.safeBrowsing);
    renderLinks(response.links);
  });
});
