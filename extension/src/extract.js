// Reads the currently open message straight from Gmail's DOM.
// Gmail's class names are obfuscated but have been stable for years; they're kept in one place here.
const GmailDom = {
  subject: "h2.hP",
  message: "div.adn.ads",          // one expanded message in a conversation
  sender: "span.gD[email]",
  body: "div.a3s",
};

const MAX_BODY = 60000;
const MAX_LINKS = 300;

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
  };
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
