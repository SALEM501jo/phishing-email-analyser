// Watches Gmail for an opened message, sends it for analysis and shows the verdict above the body.
// Gmail is a single-page app, so we observe DOM changes instead of page loads.
const results = new Map(); // message id -> { status, result?, message?, usedRawHeaders? }
let scheduled = null;

function schedule() {
  clearTimeout(scheduled);
  scheduled = setTimeout(scan, 400);
}

async function scan() {
  const open = findOpenMessage();
  if (!open) return;

  const extracted = extractEmail(open);
  const id = messageId(open.root) ?? `${extracted.senderEmail}|${extracted.subject}`;

  let banner = open.root.querySelector(BANNER_TAG);
  if (!banner) {
    banner = createBanner();
    open.body.parentElement.insertBefore(banner, open.body);
  }

  if (results.has(id)) {
    banner._render(results.get(id)); // Gmail re-rendered the message; restore the cached verdict
    return;
  }

  const language = guessLanguage(`${extracted.subject} ${extracted.body}`);
  const pending = { status: "pending", language };
  results.set(id, pending);
  banner._render(pending);

  const settings = await chrome.storage.sync.get({ fetchRawHeaders: true });
  const rawHeaders = settings.fetchRawHeaders ? await fetchRawHeaders(messageId(open.root)) : null;

  const response = await chrome.runtime
    .sendMessage({ type: "analyse", email: { ...extracted, rawHeaders } })
    .catch((e) => ({ ok: false, error: e.message }));

  const state = response?.ok
    ? { status: "done", result: response.result, usedRawHeaders: !!rawHeaders }
    : { status: "error", message: response?.error ?? "no response", language };

  if (state.status === "error") results.delete(id); // allow a retry next time the message is opened
  else results.set(id, state);

  // Re-query: Gmail may have replaced the node while we were waiting.
  (findOpenMessage()?.root.querySelector(BANNER_TAG) ?? banner)._render(state);
}

/** Quick local guess so the "scanning"/"offline" states already use the email's language. */
function guessLanguage(text) {
  const letters = text.match(/\p{L}/gu) ?? [];
  const arabic = letters.filter((ch) => /[؀-ۿ]/.test(ch)).length;
  return letters.length > 0 && arabic / letters.length >= 0.4 ? "ar" : "en";
}

new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
window.addEventListener("hashchange", schedule);
schedule();
