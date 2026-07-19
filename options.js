// options.js — runs in the extension's options page (a normal tab, unlike
// the popup, so it stays open and doesn't tear down when it loses focus).
// Reads/writes the Safe Browsing API key via chrome.storage.local, which
// persists on disk across browser restarts and is only readable by this
// extension, not by web pages or other extensions.

const input = document.getElementById("api-key");
const statusEl = document.getElementById("status");

chrome.storage.local.get(["safeBrowsingApiKey"], (result) => {
  if (result.safeBrowsingApiKey) {
    input.value = result.safeBrowsingApiKey;
  }
});

document.getElementById("save").addEventListener("click", () => {
  const key = input.value.trim();
  if (!key) {
    statusEl.textContent = "Enter a key before saving.";
    statusEl.className = "";
    return;
  }
  chrome.storage.local.set({ safeBrowsingApiKey: key }, () => {
    statusEl.textContent = "Saved. Safe Browsing checks are now enabled.";
    statusEl.className = "saved";
  });
});

document.getElementById("clear").addEventListener("click", () => {
  chrome.storage.local.remove("safeBrowsingApiKey", () => {
    input.value = "";
    statusEl.textContent = "Cleared. Safe Browsing checks are now disabled.";
    statusEl.className = "";
  });
});
