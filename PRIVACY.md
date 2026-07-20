# Link Safety Checker — Privacy Policy

_Last updated: July 19, 2026_

Link Safety Checker is a Chrome extension that flags suspicious links on the pages you visit and shows the current page's connection security in the toolbar. This page explains what data the extension touches and what it does with it.

## Short version

The extension does not collect, store, or transmit any of your data to us. It has no server, no analytics, and no tracking of any kind. Everything it does happens locally in your browser, with one narrow exception described below.

## What the extension reads

To flag suspicious links, a content script reads the links (`<a>` tags) on the pages you visit — their visible text and destination URL — entirely on your device. This analysis never leaves your browser and is never sent to us or anyone else.

To show a connection-security badge, the extension checks whether the current page's URL uses HTTPS and whether Chrome reported a certificate error for it. This uses information Chrome already has about the page you're on; nothing is sent externally for this either.

## The one exception: Google Safe Browsing

Optionally, you can enter your own free Google Safe Browsing API key in the extension's settings. If — and only if — you've configured a key, the extension sends the URL of the page you're currently on directly from your browser to Google's Safe Browsing API, to check it against Google's list of known malicious sites. That request goes straight to Google over HTTPS; it does not pass through us or any server we control. Google's handling of that request is governed by [Google's own privacy policy](https://policies.google.com/privacy).

If you don't configure an API key, this never happens and no page URLs are sent anywhere.

Your API key itself is stored only in Chrome's local, per-extension storage on your device (`chrome.storage.local`). It is never transmitted to us, and is only ever sent to Google as part of the Safe Browsing requests described above.

## What we (the developer) receive

Nothing. We do not operate any server that this extension talks to, we do not receive your browsing history, the pages you visit, the links on them, or your API key. There is no remote logging or analytics built into the extension.

## Permissions

- **Host permissions (all http/https sites):** required so the content script can scan links and the extension can report a page's connection security, regardless of which site you're on.
- **`webRequest` (read-only):** used only to detect certificate errors on the page you navigate to, so the toolbar badge matches what Chrome itself is telling you. The extension does not request `webRequestBlocking` and cannot modify or block your traffic.
- **`storage`:** used to save your optional Safe Browsing API key locally, and to keep per-tab security state consistent if Chrome restarts the extension's background process.

## Changes to this policy

If this policy changes, the "Last updated" date above will change accordingly. Material changes will also be reflected in the extension's Chrome Web Store listing.

## Contact

Questions about this policy can be raised via [the project's GitHub issues page](https://github.com/SeyKoku/link-safety-checker/issues).
