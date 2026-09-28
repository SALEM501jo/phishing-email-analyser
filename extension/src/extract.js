// Reads the currently open message straight from Gmail's DOM.
// Gmail's class names are obfuscated but have been stable for years; they're kept in one place here.
const GmailDom = {
  subject: "h2.hP",
  message: "div.adn.ads",          // one expanded message in a conversation
  sender: "span.gD[email]",
  body: "div.a3s",
  attachment: "[download_url]",   // attachment chip; attribute = "mime/type:filename:url"
  attachmentName: "span.aV3",     // fallback: file name label on the chip
};

const MAX_BODY = 60000;
const MAX_LINKS = 300;
const MAX_QR_IMAGES = 5;

// Only images Gmail itself serves (its image proxy or attachment URLs) - never the sender's own servers,
// where fetching an image (a tracking pixel) would tell the sender the email was opened.
const QR_IMAGE_HOSTS = /^https:\/\/([a-z0-9-]+\.googleusercontent\.com|mail\.google\.com)\//i;

/** Returns the last expanded message in the open conversation, or null. */
function findOpenMessage() {
  const messages = document.querySelectorAll(GmailDom.message);
  for (let i = messages.length - 1; i >= 0; i--) {
    const body = messages[i].querySelector(GmailDom.body);
    if (body && body.offsetParent !== null) return { root: messages[i], body };
  }
  return null;
}

/** Stable id for the message: Gmail's permanent id when available. */
function messageId(root) {
  const id = root.querySelector("[data-message-id]")?.getAttribute("data-message-id")
    || root.getAttribute("data-message-id")
    || root.querySelector("[data-legacy-message-id]")?.getAttribute("data-legacy-message-id");
  return id ? id.replace(/^#/, "") : null;
}

function extractEmail({ root, body }) {
  const senderEl = root.querySelector(GmailDom.sender);

  const links = [];
  for (const a of body.querySelectorAll("a[href]")) {
    if (links.length >= MAX_LINKS) break;
    const href = a.getAttribute("href");
    if (!href || href.startsWith("#")) continue;
    links.push({ text: a.innerText.trim().slice(0, 300), href });
  }

  return {
    subject: document.querySelector(GmailDom.subject)?.innerText.trim() ?? "",
    senderName: senderEl?.getAttribute("name") ?? senderEl?.innerText.trim() ?? "",
    senderEmail: senderEl?.getAttribute("email") ?? "",
    body: body.innerText.slice(0, MAX_BODY),
    links,
    attachments: extractAttachments(root),
  };
}

/** Attachment names and types from Gmail's attachment chips - the files themselves are never read. */
function extractAttachments(root) {
  const found = new Map();
  for (const chip of root.querySelectorAll(GmailDom.attachment)) {
    const [mimeType, name] = (chip.getAttribute("download_url") ?? "").split(":");
    if (name) found.set(name, { name, mimeType });
  }
  if (found.size === 0) {
    for (const label of root.querySelectorAll(GmailDom.attachmentName)) {
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
 * Best effort: fetch Gmail's "Show original" view (same origin, user's own session) and return only the
 * header block. This is what makes real SPF/DKIM/DMARC checks possible without the Gmail API.
 */
async function fetchRawHeaders(msgId) {
  const ik = document.documentElement.dataset.paIk;
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
    if (!raw) return null;
    const end = raw.search(/\r?\n\r?\n/);
    return (end > 0 ? raw.slice(0, end) : raw).slice(0, 60000);
  } catch {
    return null;
  }
}
