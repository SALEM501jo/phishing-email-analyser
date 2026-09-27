const DEFAULTS = { apiUrl: "http://localhost:5080", apiKey: "", fetchRawHeaders: true };
const $ = (id) => document.getElementById(id);

chrome.storage.sync.get(DEFAULTS).then((s) => {
  $("apiUrl").value = s.apiUrl;
  $("apiKey").value = s.apiKey;
  $("fetchRawHeaders").checked = s.fetchRawHeaders;
});

$("save").addEventListener("click", async () => {
  const status = $("status");
  let url;
  try {
    url = new URL($("apiUrl").value.trim() || DEFAULTS.apiUrl);
  } catch {
    status.textContent = "Invalid URL";
    return;
  }

  // Remote servers need a host permission; request it now (must happen inside the click handler).
  const origin = `${url.origin}/*`;
  if (!(await chrome.permissions.contains({ origins: [origin] }))) {
    const granted = await chrome.permissions.request({ origins: [origin] });
    if (!granted) {
      status.textContent = "Permission for that server was denied";
      return;
    }
  }

  await chrome.storage.sync.set({
    apiUrl: url.origin + url.pathname.replace(/\/+$/, ""),
    apiKey: $("apiKey").value.trim(),
    fetchRawHeaders: $("fetchRawHeaders").checked,
  });
  status.textContent = "Saved";
  setTimeout(() => (status.textContent = ""), 2000);
});
