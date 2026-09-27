// Service worker: the only part of the extension that talks to the API.
// Doing the request here (not in the content script) keeps the API key out of Gmail's page
// and avoids CORS, since the extension holds host permission for the API origin.
const DEFAULTS = { apiUrl: "http://localhost:5080", apiKey: "" };
const TIMEOUT_MS = 15000;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "analyse" || !sender.url?.startsWith("https://mail.google.com/")) return false;

  analyse(message.email)
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

chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());
