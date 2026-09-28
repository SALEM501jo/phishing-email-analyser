const DEFAULTS = { apiUrl: "http://localhost:5080", apiKey: "", fetchRawHeaders: true, privacyMode: "full", shareEmailWithFeedback: false };
const $ = (id) => document.getElementById(id);

chrome.storage.sync.get(DEFAULTS).then((s) => {
  $("apiUrl").value = s.apiUrl;
  $("apiKey").value = s.apiKey;
  $("fetchRawHeaders").checked = s.fetchRawHeaders;
  $("shareEmailWithFeedback").checked = s.shareEmailWithFeedback;
  document.querySelector(`input[name=privacyMode][value=${s.privacyMode}]`).checked = true;
});

/** Plain HTTP is only acceptable to this machine; anything else must be HTTPS (email content is in the request). */
function isAllowedApiUrl(url) {
  return url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname));
}

function show(message, ok) {
  const status = $("status");
  status.textContent = message;
  status.className = ok ? "ok" : "err";
}

$("save").addEventListener("click", async () => {
  let url;
  try {
    url = new URL($("apiUrl").value.trim() || DEFAULTS.apiUrl);
  } catch {
    return show("Invalid URL", false);
  }
  if (!isAllowedApiUrl(url)) return show("Use https:// - plain http is only allowed for localhost", false);

  // Remote servers need a host permission; request it now (must happen inside the click handler).
  const origin = `${url.origin}/*`;
  if (!(await chrome.permissions.contains({ origins: [origin] })) && !(await chrome.permissions.request({ origins: [origin] })))
    return show("Permission for that server was denied", false);

  await chrome.storage.sync.set({
    apiUrl: url.origin + url.pathname.replace(/\/+$/, ""),
    apiKey: $("apiKey").value.trim(),
    fetchRawHeaders: $("fetchRawHeaders").checked,
    shareEmailWithFeedback: $("shareEmailWithFeedback").checked,
    privacyMode: document.querySelector("input[name=privacyMode]:checked")?.value ?? "full",
  });
  show("Saved", true);
  setTimeout(() => ($("status").textContent = ""), 2000);
});

// Diagnostics: which strategy located each part of Gmail's page (index into extract.js GmailDom lists).
const STRATEGY_NAMES = {
  message: ["div.adn.ads (primary)", "div[data-message-id]", "listitem fallback"],
  body: ["div.a3s (primary)", "dir=ltr fallback", "dir=rtl fallback", "largest-text heuristic"],
  sender: ["span.gD (primary)", "h3 span[email]", "span[email][name]", "[email]"],
  subject: ["h2.hP (primary)", "h2[data-thread-perm-id]", "role=main h2"],
};

chrome.storage.local.get({ lastDiagnostics: null }).then(({ lastDiagnostics: d }) => {
  if (!d) return;
  const table = $("diagnostics");
  table.replaceChildren();
  const row = (name, value, good) => {
    const tr = document.createElement("tr");
    const a = document.createElement("td"); a.textContent = name;
    const b = document.createElement("td"); b.textContent = value; b.className = good ? "ok" : "err";
    tr.append(a, b);
    table.append(tr);
  };
  row("Scanned at", new Date(d.at).toLocaleString(), true);
  for (const part of ["message", "body", "sender", "subject"]) {
    const index = d[part];
    row(part, index === undefined ? "not reached" : index < 0 ? "NOT FOUND" : STRATEGY_NAMES[part][index] ?? `strategy ${index}`, index >= 0);
  }
  if (d.ik !== undefined) row("Gmail 'ik' token", d.ik ? "found" : "not found", d.ik);
  if (d.rawHeaders !== undefined) row("Show original headers", d.rawHeaders ? "read" : "not read", d.rawHeaders);
  if (d.links !== undefined) row("Links / attachments", `${d.links} / ${d.attachments}`, true);
  row("Result", d.ok ? "analysed" : d.layoutRecognised === false ? "Gmail layout not recognised" : "failed", d.ok);
});
