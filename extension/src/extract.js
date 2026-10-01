// Reads the currently open message straight from Gmail's DOM.
//
// Gmail's class names are obfuscated (h2.hP, span.gD ...) and Google can change them at any time. Every element is
// therefore located by an ordered list of strategies: the known class names first, then fallbacks built on
// attributes Gmail relies on functionally (email="", data-message-id, role="main", dir=""). Which strategy
// matched is recorded in a diagnostics report - never any email content - so a layout change is visible
// instead of the extension silently doing nothing.
const GmailDom = {
  subject: ["h2.hP", "h2[data-thread-perm-id]", "[role='main'] h2"],
  message: ["div.adn.ads", "div[data-message-id]", "[role='listitem'] [data-legacy-message-id]"],
  sender: ["span.gD[email]", "h3 span[email]", "span[email][name]", "[email]"],
  body: ["div.a3s", "div[data-message-id] div[dir='ltr']", "div[data-message-id] div[dir='rtl']"],
  attachment: ["[download_url]"],   // attachment chip; attribute = "mime/type:filename:url"
  attachmentName: ["span.aV3"],     // fallback: file name label on the chip
};

const MAX_BODY = 60000;
const MAX_LINKS = 300;
const MAX_LINK_CANDIDATES = 5000; // bound on the work for an email stuffed with links
const MAX_QR_IMAGES = 5;
const MAX_MESSAGES = 10;          // expanded messages of one thread analysed per scan (newest first)

// Only images Gmail itself serves (its image proxy or attachment URLs) - never the sender's own servers,
// where fetching an image (a tracking pixel) would tell the sender the email was opened.
const QR_IMAGE_HOSTS = /^https:\/\/([a-z0-9-]+\.googleusercontent\.com|mail\.google\.com)\//i;

/** First element matched by the ordered strategies, plus the index of the strategy that worked. */
function locate(root, strategies) {
  for (let i = 0; i < strategies.length; i++) {
    const el = root.querySelector(strategies[i]);
    if (el) return { el, strategy: i };
  }
  return { el: null, strategy: -1 };
}

function locateAll(root, strategies) {
  for (let i = 0; i < strategies.length; i++) {
    const found = root.querySelectorAll(strategies[i]);
    if (found.length) return { els: [...found], strategy: i };
  }
  return { els: [], strategy: -1 };
}

/**
 * Last-resort body detection: the innermost block that still holds (almost) all of the message's text.
 * Outer wrappers also contain the sender header etc., so among blocks with >= 90% of the largest text length,
 * the smallest one is the body.
 */
function largestTextBlock(root) {
  const blocks = [...root.querySelectorAll("div")].map((div) => ({ div, length: div.innerText?.length ?? 0 }));
  const max = Math.max(0, ...blocks.map((b) => b.length));
  if (max < 20) return null;
  return blocks.filter((b) => b.length >= max * 0.9).sort((a, b) => a.length - b.length)[0].div;
}

/**
 * Every expanded, visible message in the open conversation, newest first. All of them are analysed: with only the
 * last one, an attacker could follow the phishing email with a harmless reply in the same thread, and the thread
 * would show a single green banner (found by the red-team review).
 */
function findOpenMessages(diagnostics = {}) {
  const { els: messages, strategy } = locateAll(document, GmailDom.message);
  diagnostics.message = strategy;
  diagnostics.body = -1;
  const open = [];
  for (let i = messages.length - 1; i >= 0 && open.length < MAX_MESSAGES; i--) {
    if (open.some((o) => o.root.contains(messages[i]) || messages[i].contains(o.root))) continue; // nested match of one message
    let { el: body, strategy: bodyStrategy } = locate(messages[i], GmailDom.body);
    if (!body) {
      body = largestTextBlock(messages[i]);
      bodyStrategy = body ? GmailDom.body.length : -1; // index past the list = heuristic fallback
    }
    if (body && body.offsetParent !== null) {
      if (open.length === 0) diagnostics.body = bodyStrategy;
      open.push({ root: messages[i], body });
    }
  }
  return open;
}

/** The last expanded, visible message in the open conversation, or null. */
function findOpenMessage(diagnostics = {}) {
  return findOpenMessages(diagnostics)[0] ?? null;
}

/**
 * Is an email open at all? Used to tell "nothing to do" apart from "an email is open but we can't read it"
 * (= Gmail changed its layout), which must be shown to the user rather than failing silently.
 */
function emailViewOpen() {
  return /#[^/]+\/[A-Za-z0-9]{16,}/.test(location.hash) || document.querySelector("[data-message-id], [data-legacy-message-id]") !== null;
}

/** Stable id for the message: Gmail's permanent id when available. */
function messageId(root) {
  const id = root.getAttribute("data-message-id")
    || root.querySelector("[data-message-id]")?.getAttribute("data-message-id")
    || root.getAttribute("data-legacy-message-id")
    || root.querySelector("[data-legacy-message-id]")?.getAttribute("data-legacy-message-id");
  return id ? id.replace(/^#/, "") : null;
}

function extractEmail({ root, body }, diagnostics = {}) {
  const sender = locate(root, GmailDom.sender);
  const subject = locate(document, GmailDom.subject);
  diagnostics.sender = sender.strategy;
  diagnostics.subject = subject.strategy;

  const links = extractLinks(body);

  const attachments = extractAttachments(root);
  diagnostics.attachments = attachments.length;
  diagnostics.links = links.length;

  return {
    subject: subject.el?.innerText.trim() ?? "",
    senderName: sender.el?.getAttribute("name") ?? sender.el?.innerText.trim() ?? "",
    senderEmail: sender.el?.getAttribute("email") ?? "",
    body: (body.innerText ?? "").slice(0, MAX_BODY),
    links,
    attachments,
  };
}

/**
 * Everything in the body that takes the reader somewhere: ordinary links, image-map areas, and forms (a form's
 * action is where a typed password goes). Reading only <a href> let an image map or a form skip every link check.
 */
function extractLinks(body) {
  const candidates = [];
  for (const el of body.querySelectorAll("a[href], area[href], form[action], [formaction]")) {
    if (candidates.length >= MAX_LINK_CANDIDATES) break;
    const tag = el.tagName.toLowerCase();
    const href = el.getAttribute(tag === "form" ? "action" : el.hasAttribute("formaction") && tag !== "a" && tag !== "area" ? "formaction" : "href");
    if (!href || href.startsWith("#")) continue;
    const text = tag === "a" ? el.innerText
      : tag === "area" ? el.getAttribute("alt") || el.getAttribute("title")
      : el.querySelector?.("button, input[type='submit']")?.innerText || el.getAttribute("value") || el.innerText;
    candidates.push({ text: (text ?? "").trim().slice(0, 300), href, el });
  }
  return selectLinks(candidates).map(({ text, href }) => ({ text, href }));
}

/**
 * At most MAX_LINKS links are sent. When there are more, visible links go first and every destination host gets a
 * turn before any host gets a second link - so hundreds of hidden or same-site decoy links can't push the one real
 * link past the cap (found by the red-team review).
 */
function selectLinks(candidates) {
  if (candidates.length <= MAX_LINKS) return candidates;
  const seen = new Map();
  const ranked = candidates.map((c, index) => {
    const hidden = isHidden(c.el);
    let host = c.href;
    try { host = new URL(c.href, location.href).host || c.href; } catch { /* unparseable: its own bucket */ }
    const key = `${hidden ? "h" : "v"}|${host}`;
    const rank = seen.get(key) ?? 0;
    seen.set(key, rank + 1);
    return { ...c, index, hidden, rank };
  });
  return ranked
    .sort((a, b) => a.hidden - b.hidden || a.rank - b.rank || a.index - b.index)
    .slice(0, MAX_LINKS)
    .sort((a, b) => a.index - b.index);
}

function isHidden(el) {
  for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (style.display === "none" || style.visibility === "hidden") return true;
  }
  return false;
}

/**
 * "mime/type:file name:https://..." - the name itself may contain ':' ("Remittance:Advice.html"), so it is everything
 * between the first ':' and the URL at the end, not simply the second ':'-separated field.
 */
function parseDownloadUrl(value) {
  const first = value.indexOf(":");
  if (first < 0) return null;
  const rest = value.slice(first + 1);
  const url = rest.search(/:https?:\/\/[^:]*$/i);
  const name = (url >= 0 ? rest.slice(0, url) : rest.split(":")[0]).trim();
  return name ? { name, mimeType: value.slice(0, first) } : null;
}

/** Attachment names and types from Gmail's attachment chips - the files themselves are never read. */
function extractAttachments(root) {
  const found = new Map();
  for (const chip of locateAll(root, GmailDom.attachment).els) {
    const parsed = parseDownloadUrl(chip.getAttribute("download_url") ?? "");
    if (parsed) found.set(parsed.name, parsed);
  }
  if (found.size === 0) {
    for (const label of locateAll(root, GmailDom.attachmentName).els) {
      const name = label.innerText.trim();
      if (name) found.set(name, { name, mimeType: null });
    }
  }
  return [...found.values()].slice(0, 50);
}

/** Inline images large enough to hold a QR code, served by Gmail (see QR_IMAGE_HOSTS). */
function qrCandidateImages(body) {
  return [...body.querySelectorAll("img")]
    .filter((img) => img.naturalWidth >= 80 && img.naturalHeight >= 80 && QR_IMAGE_HOSTS.test(img.currentSrc || img.src))
    .map((img) => img.currentSrc || img.src)
    .slice(0, MAX_QR_IMAGES);
}

/**
 * Gmail's per-account "ik" token, needed for the "Show original" URL. Primary source: gmail-main-world.js reads
 * window.GLOBALS[9]. Fallback: the same array is declared in an inline <script> ("var GLOBALS=[...]"), whose
 * text the isolated content script can read.
 */
function gmailIk() {
  const fromMainWorld = document.documentElement.dataset.paIk;
  if (fromMainWorld) return fromMainWorld;
  for (const script of document.querySelectorAll("script:not([src])")) {
    const start = script.textContent.search(/GLOBALS\s*=\s*\[/);
    if (start < 0) continue;
    const literal = arrayLiteralAt(script.textContent, script.textContent.indexOf("[", start));
    try {
      const ik = JSON.parse(literal)[9];
      if (typeof ik === "string" && /^[0-9a-f]{6,16}$/i.test(ik)) return ik;
    } catch {
      // not plain JSON - give up on this fallback rather than guess
    }
  }
  return null;
}

/** The complete "[...]" starting at `open`, respecting nesting and string literals (commas and brackets inside strings). */
function arrayLiteralAt(text, open) {
  let depth = 0;
  let quote = null;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "[") depth++;
    else if (ch === "]" && --depth === 0) return text.slice(open, i + 1);
  }
  return "";
}

/**
 * Best effort: fetch Gmail's "Show original" view (same origin, user's own session) and return only the
 * header block. This is what makes real SPF/DKIM/DMARC checks possible without the Gmail API.
 */
async function fetchRawHeaders(msgId, diagnostics = {}) {
  const ik = gmailIk();
  diagnostics.ik = Boolean(ik);
  const account = location.pathname.match(/\/mail\/u\/(\d+)/)?.[1] ?? "0";
  if (!ik || !msgId) return null;

  const permId = msgId.startsWith("msg-") ? msgId : `msg-f:${BigInt("0x" + msgId).toString()}`;
  const url = `${location.origin}/mail/u/${account}/?ik=${encodeURIComponent(ik)}&view=om&permmsgid=${encodeURIComponent(permId)}`;

  try {
    const res = await fetch(url, { credentials: "include" });
    if (!res.ok) return null;
    const html = await res.text();
    const doc = new DOMParser().parseFromString(html, "text/html");
    const raw = doc.querySelector("#raw_message_text")?.textContent;
    diagnostics.rawHeaders = Boolean(raw);
    if (!raw) return null;
    const end = raw.search(/\r?\n\r?\n/);
    return (end > 0 ? raw.slice(0, end) : raw).slice(0, 60000);
  } catch {
    diagnostics.rawHeaders = false;
    return null;
  }
}
