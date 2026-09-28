// Service worker: the only part of the extension that talks to the API.
// Doing the request here (not in the content script) keeps the API key out of Gmail's page
// and avoids CORS, since the extension holds host permission for the API origin.
importScripts("../vendor/jsQR.js"); // pinned + verified copy, see vendor/README.md

const DEFAULTS = { apiUrl: "http://localhost:5080", apiKey: "" };
const TIMEOUT_MS = 15000;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const GMAIL_IMAGE = /^https:\/\/([a-z0-9-]+\.googleusercontent\.com|mail\.google\.com)\//i;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "analyse" || !sender.url?.startsWith("https://mail.google.com/")) return false;

  decodeQrCodes(message.qrImages ?? [])
    .then((qrCodeUrls) => analyse({ ...message.email, qrCodeUrls }))
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: error.message }));
  return true; // keep the channel open for the async response
});

async function analyse(email) {
  const { apiUrl, apiKey } = await chrome.storage.sync.get(DEFAULTS);
  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["X-Api-Key"] = apiKey;

  const res = await fetch(`${apiUrl.replace(/\/+$/, "")}/api/v1/analyse`, {
    method: "POST",
    headers,
    body: JSON.stringify(email),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });

  if (res.status === 401) throw new Error("API key rejected - check the extension options");
  if (res.status === 429) throw new Error("rate limited, try again in a minute");
  if (!res.ok) throw new Error(`API returned ${res.status}`);
  return res.json();
}

/**
 * QR codes are decoded HERE, in the browser: the images never leave the machine, only the decoded URLs are
 * sent for analysis. Only Gmail-served image URLs are accepted (re-checked here, not trusted from the page).
 */
async function decodeQrCodes(imageUrls) {
  const urls = [];
  for (const src of imageUrls.slice(0, 5)) {
    if (!GMAIL_IMAGE.test(src)) continue;
    try {
      const res = await fetch(src, { credentials: "include", signal: AbortSignal.timeout(4000) });
      const blob = await res.blob();
      if (!res.ok || blob.size > MAX_IMAGE_BYTES || !blob.type.startsWith("image/")) continue;

      const bitmap = await createImageBitmap(blob);
      const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height)); // bound the work on huge images
      const width = Math.round(bitmap.width * scale), height = Math.round(bitmap.height * scale);
      const canvas = new OffscreenCanvas(width, height);
      const ctx = canvas.getContext("2d");
      ctx.drawImage(bitmap, 0, 0, width, height);
      const code = jsQR(ctx.getImageData(0, 0, width, height).data, width, height);
      if (code?.data && /^https?:\/\//i.test(code.data.trim())) urls.push(code.data.trim().slice(0, 2048));
    } catch {
      // unreadable image - skip it
    }
  }
  return [...new Set(urls)];
}

chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());
