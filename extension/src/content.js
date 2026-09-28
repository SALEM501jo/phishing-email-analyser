// Watches Gmail for an opened message, sends it for analysis and shows the verdict above the body.
// Gmail is a single-page app, so we observe DOM changes instead of page loads.
const results = new Map(); // message id -> { status, result?, message?, usedRawHeaders? }
let scheduled = null;
let layoutWarningShown = false;

const SETTINGS = { fetchRawHeaders: true, privacyMode: "full" }; // "full" | "metadata" (no body text leaves the browser)

function schedule() {
  clearTimeout(scheduled);
  scheduled = setTimeout(scan, 400);
}

async function scan() {
  const diagnostics = { at: new Date().toISOString() };
  const open = findOpenMessage(diagnostics);
  if (!open) {
    // An email is clearly open but none of the strategies can read it: Gmail's layout changed.
    // Say so instead of silently doing nothing.
    if (emailViewOpen()) showLayoutWarning(diagnostics);
    return;
  }

  const extracted = extractEmail(open, diagnostics);
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

  const settings = await chrome.storage.sync.get(SETTINGS);
  const rawHeaders = settings.fetchRawHeaders ? await fetchRawHeaders(messageId(open.root), diagnostics) : null;
  const metadataOnly = settings.privacyMode === "metadata";
  const email = { ...extracted, body: metadataOnly ? "" : extracted.body, rawHeaders };

  const qrImages = qrCandidateImages(open.body);
  const response = await chrome.runtime
    .sendMessage({ type: "analyse", email, qrImages })
    .catch((e) => ({ ok: false, error: e.message }));

  const state = response?.ok
    ? {
        status: "done", result: response.result, usedRawHeaders: !!rawHeaders, metadataOnly,
        // 👍/👎 on the banner. Only the verdict and reason codes are sent - the email itself only if the user
        // explicitly opted in (options page), and never in metadata-only mode.
        onFeedback: (correct) => chrome.runtime.sendMessage({
          type: "feedback", correct, result: response.result, email: metadataOnly ? null : extracted,
        }),
      }
    : { status: "error", message: response?.error ?? "no response", language };

  if (state.status === "error") results.delete(id); // allow a retry next time the message is opened
  else results.set(id, state);

  saveDiagnostics({ ...diagnostics, ok: state.status === "done" });

  // Re-query: Gmail may have replaced the node while we were waiting.
  (findOpenMessage()?.root.querySelector(BANNER_TAG) ?? banner)._render(state);
}

/** Shows a one-off banner at the top of the reading pane when the email can't be read. */
function showLayoutWarning(diagnostics) {
  saveDiagnostics({ ...diagnostics, ok: false, layoutRecognised: false });
  if (layoutWarningShown) return;
  const main = document.querySelector("[role='main']");
  if (!main) return;
  layoutWarningShown = true;
  const banner = createBanner();
  main.prepend(banner);
  banner._render({ status: "unsupported", language: document.documentElement.lang?.startsWith("ar") ? "ar" : "en" });
}

/**
 * Keeps the last scan's diagnostics (which selector strategy worked - never any email content) so the options
 * page can show them; this is what makes a Gmail layout change easy to spot and report.
 */
function saveDiagnostics(report) {
  chrome.storage.local.set({ lastDiagnostics: report }).catch(() => {});
}

/** Quick local guess so the "scanning"/"offline" states already use the email's language. */
function guessLanguage(text) {
  const letters = text.match(/\p{L}/gu) ?? [];
  const arabic = letters.filter((ch) => ch.codePointAt(0) >= 0x600 && ch.codePointAt(0) <= 0x6ff).length;
  return letters.length > 0 && arabic / letters.length >= 0.4 ? "ar" : "en";
}

// Guarded so the file can also be loaded by the unit tests, where there's no extension runtime.
if (typeof chrome !== "undefined" && chrome.runtime?.id) {
  new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
  window.addEventListener("hashchange", schedule);
  schedule();
}
