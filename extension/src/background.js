// Service worker: the only part of the extension that talks to the API.
// Doing the request here (not in the content script) keeps the API key out of Gmail's page
// and avoids CORS, since the extension holds host permission for the API origin.
importScripts("../vendor/jsQR.js"); // pinned + verified copy, see vendor/README.md

const DEFAULTS = { apiUrl: "http://localhost:5080", apiKey: "" };
const TIMEOUT_MS = 15000;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const GMAIL_IMAGE = /^https:\/\/([a-z0-9-]+\.googleusercontent\.com|mail\.google\.com)\//i;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!sender.url?.startsWith("https://mail.google.com/")) return false;

  if (message?.type === "feedback") {
    sendFeedback(message).then(() => sendResponse({ ok: true })).catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (message?.type !== "analyse") return false;

  decodeQrCodes(message.qrImages ?? [])
    .then((qrCodeUrls) => analyse({ ...message.email, qrCodeUrls }))
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: error.message }));
  return true; // keep the channel open for the async response
});

/** Email content only ever travels over HTTPS - plain HTTP is accepted for this machine alone. */
function assertSecure(apiUrl) {
  const url = new URL(apiUrl);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local))
    throw new Error("API URL must use https:// (see extension options)");
}

async function analyse(email) {
  const { apiUrl, apiKey } = await chrome.storage.sync.get(DEFAULTS);
  assertSecure(apiUrl);
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
 * 👍/👎 feedback. By default only what the API already returned is sent back (verdict, score, reason codes,
 * model version) - enough to measure false positives/negatives. The email itself is attached only when the
 * user opted in on the options page, so it can be used as labelled training data.
 */
async function sendFeedback({ correct, result, email }) {
  const { apiUrl, apiKey, shareEmailWithFeedback } = await chrome.storage.sync.get({ ...DEFAULTS, shareEmailWithFeedback: false });
  assertSecure(apiUrl);
  const b = result.breakdown ?? {};
  const reasonCodes = [b.headers, b.links, b.reputation, b.attachments, b.obfuscation]
    .flatMap((c) => c?.findings ?? []).filter((f) => f.weight > 0).map((f) => f.code);

  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["X-Api-Key"] = apiKey;
  const res = await fetch(`${apiUrl.replace(/\/+$/, "")}/api/v1/feedback`, {
    method: "POST",
    headers,
    signal: AbortSignal.timeout(TIMEOUT_MS),
    body: JSON.stringify({
      correct,
      verdict: result.verdict,
      score: result.score,
      modelVersion: result.modelVersion,
      language: result.language,
      reasonCodes: [...new Set(reasonCodes)],
      phishingProbability: b.content?.probability,
      // Clamped to the API's limits: an over-long field would make the API reject the whole report.
      email: shareEmailWithFeedback && email
        ? {
            subject: (email.subject ?? "").slice(0, 1000),
            senderEmail: (email.senderEmail ?? "").slice(0, 320),
            body: (email.body ?? "").slice(0, 20000),
            links: (email.links ?? []).slice(0, 50).map((l) => ({ text: (l.text ?? "").slice(0, 300), href: (l.href ?? "").slice(0, 2048) })),
          }
        : null,
    }),
  });
  if (!res.ok) throw new Error(`feedback API returned ${res.status}`);
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
